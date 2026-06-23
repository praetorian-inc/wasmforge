//go:build windows

package hostmod

import (
	"context"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

// win32Errno converts a Windows error to a uint32 error code returned to the
// WASM guest. Win32 host functions pass through raw Windows error codes so that
// guest code can handle Win32-specific error semantics (e.g., ERROR_NO_MORE_ITEMS=259,
// ERROR_MORE_DATA=234). Transport-level errors (ENOSYS, EFAULT, EBADF) are
// returned directly by the host functions before reaching this helper.
func win32Errno(err error) uint32 {
	if err == nil {
		return errnoSuccess
	}
	if errno, ok := err.(syscall.Errno); ok {
		return uint32(errno)
	}
	return errnoEINVAL
}

// semanticOverrides provides hand-curated pointer masks for APIs where the
// type-level classification from win32metadata is semantically incorrect.
// These take priority over generatedPointerMasks (from gen-ptrmasks).
//
// The primary case is cross-process memory APIs where PointerTo(Void)
// parameters are actually remote process addresses, not WASM linear memory
// pointers. The metadata cannot distinguish local vs remote pointers.
//
// Bit N=1 means arg[N] IS a WASM pointer; bit N=0 means it is NOT.
var semanticOverrides = map[string]uint32{
	// --- Cross-process memory manipulation (execute-assembly) ---
	// VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocType, flProtect)
	// No WASM pointers: handle, remote addr (0), SIZE, flags, flags
	"VirtualAllocEx": 0x00,

	// WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, *lpBytesWritten)
	// arg[2]=lpBuffer is WASM ptr, arg[4]=lpBytesWritten is WASM ptr
	// lpBaseAddress is REMOTE addr (metadata says PointerTo but it's another process)
	"WriteProcessMemory": 1<<2 | 1<<4, // 0x14

	// ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, *lpBytesRead)
	// arg[2]=lpBuffer is WASM ptr, arg[4]=lpBytesRead is WASM ptr
	// lpBaseAddress is REMOTE addr
	"ReadProcessMemory": 1<<2 | 1<<4, // 0x14

	// CreateRemoteThread(hProcess, lpSA, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, *lpThreadId)
	// arg[1]=lpSA (usually 0, can be WASM ptr), arg[6]=lpThreadId is WASM ptr
	// arg[3]=lpStartAddress is REMOTE addr, arg[4]=lpParameter is REMOTE addr
	"CreateRemoteThread": 1<<1 | 1<<6, // 0x42

	// CreateRemoteThreadEx — same pattern as CreateRemoteThread
	// (hProcess, lpSA, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, *lpThreadId, lpAttributeList)
	"CreateRemoteThreadEx": 1<<1 | 1<<6, // 0x42

	// VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, *lpflOldProtect)
	// arg[4]=lpflOldProtect is WASM ptr; lpAddress is REMOTE addr, dwSize is SIZE
	"VirtualProtectEx": 1 << 4, // 0x10

	// VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType)
	// All non-WASM: handle, remote addr, size, flags
	"VirtualFreeEx": 0x00,

	// VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength)
	// lpAddress is REMOTE addr; lpBuffer is WASM ptr for output
	"VirtualQueryEx": 0x04, // bit 2 only

	// NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)
	// BaseAddress is REMOTE; Buffer and NumberOfBytesWritten are WASM ptrs
	"NtWriteVirtualMemory": 1<<2 | 1<<4, // 0x14

	// NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead)
	"NtReadVirtualMemory": 1<<2 | 1<<4, // 0x14

	// --- Handle operations (no WASM pointers at all) ---
	// OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
	"OpenProcess": 0x00,

	// --- BCrypt (CNG) APIs used by WfForge/WfCsr ---
	// These return 64-bit BCRYPT_*_HANDLE values whose low 32 bits often
	// fall inside the wasm32 memory range (typical heap addresses are well
	// under 4 GB on modern Win11 bcrypt.dll). Without an explicit mask, the
	// host's heuristic would incorrectly translate the handle on subsequent
	// calls. Masks enumerate WHICH args are real WASM pointers; everything
	// else (handles, sizes, flags) is passed through untouched.

	// BCryptOpenAlgorithmProvider(phAlgorithm, pszAlgId, pszImplementation, dwFlags)
	// arg[0]=phAlgorithm (out 8-byte handle slot in WASM) — WASM ptr
	// arg[1]=pszAlgId (LPCWSTR, in WASM) — WASM ptr
	// arg[2]=pszImplementation (LPCWSTR, often NULL) — WASM ptr if non-NULL
	// arg[3]=dwFlags — scalar
	"BCryptOpenAlgorithmProvider": 1<<0 | 1<<1 | 1<<2, // 0x07

	// BCryptCloseAlgorithmProvider(hAlgorithm, dwFlags) — no WASM ptrs
	"BCryptCloseAlgorithmProvider": 0x00,

	// BCryptGenerateKeyPair(hAlgorithm, phKey, dwLength, dwFlags)
	// arg[0]=hAlgorithm — handle (NOT WASM ptr)
	// arg[1]=phKey (out 8-byte handle slot in WASM) — WASM ptr
	"BCryptGenerateKeyPair": 1 << 1, // 0x02

	// BCryptFinalizeKeyPair(hKey, dwFlags) — no WASM ptrs
	"BCryptFinalizeKeyPair": 0x00,

	// BCryptDestroyKey(hKey) — no WASM ptrs
	"BCryptDestroyKey": 0x00,

	// BCryptExportKey(hKey, hExportKey, pszBlobType, pbOutput, cbOutput, pcbResult, dwFlags)
	// arg[0]=hKey — handle
	// arg[1]=hExportKey — handle (often 0)
	// arg[2]=pszBlobType (LPCWSTR) — WASM ptr
	// arg[3]=pbOutput (output buffer) — WASM ptr
	// arg[4]=cbOutput — scalar size
	// arg[5]=pcbResult (out ULONG) — WASM ptr
	// arg[6]=dwFlags — scalar
	"BCryptExportKey": 1<<2 | 1<<3 | 1<<5, // 0x2C

	// BCryptSignHash(hKey, pPaddingInfo, pbInput, cbInput, pbOutput, cbOutput, pcbResult, dwFlags)
	// arg[0]=hKey — handle
	// arg[1]=pPaddingInfo (input struct) — WASM ptr
	// arg[2]=pbInput (input buffer) — WASM ptr
	// arg[3]=cbInput — scalar
	// arg[4]=pbOutput (output buffer) — WASM ptr
	// arg[5]=cbOutput — scalar
	// arg[6]=pcbResult (out ULONG) — WASM ptr
	// arg[7]=dwFlags — scalar
	"BCryptSignHash": 1<<1 | 1<<2 | 1<<4 | 1<<6, // 0x56

	// BCryptHash(hAlgorithm, pbSecret, cbSecret, pbInput, cbInput, pbOutput, cbOutput)
	// arg[0]=hAlgorithm — handle
	// arg[1]=pbSecret — WASM ptr (may be NULL)
	// arg[2]=cbSecret — scalar
	// arg[3]=pbInput — WASM ptr
	// arg[4]=cbInput — scalar
	// arg[5]=pbOutput — WASM ptr
	// arg[6]=cbOutput — scalar
	"BCryptHash": 1<<1 | 1<<3 | 1<<5, // 0x2A

	// --- crypt32.dll APIs used by WfCertStore (manageself verb) ---
	// Cert store handles (HCERTSTORE) and CERT_CONTEXT pointers (PCCERT_CONTEXT)
	// are real HOST addresses returned by the API. Their low halves often fall
	// inside the wasm32 memory range; the heuristic must NOT translate them.

	// CertOpenSystemStoreW(hProv, lpszStoreName) — returns HCERTSTORE
	// arg[0]=hProv — handle (typically 0)
	// arg[1]=lpszStoreName — LPCWSTR in WASM
	"CertOpenSystemStoreW": 1 << 1, // 0x02

	// CertEnumCertificatesInStore(hCertStore, pPrevCertContext) — returns PCCERT_CONTEXT
	// Both args are HOST pointers/handles. Pass through unchanged.
	"CertEnumCertificatesInStore": 0x00,

	// CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)
	// arg[0]=pCertContext — HOST pointer (NOT a WASM offset)
	// arg[1]=dwType, arg[2]=dwFlags — scalars
	// arg[3]=pvTypePara — usually NULL; can be a HOST or WASM ptr depending on dwType
	// arg[4]=pszNameString — WASM out buffer
	// arg[5]=cchNameString — scalar (char count)
	"CertGetNameStringW": 1 << 4, // 0x10

	// CertCloseStore(hCertStore, dwFlags) — handle + scalar
	"CertCloseStore": 0x00,

	// --- ole32.dll APIs used by WfCom (manageca and other COM verbs) ---

	// CoInitializeEx(pvReserved, dwCoInit) — both scalars (NULL + flag)
	"CoInitializeEx": 0x00,

	// CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv)
	// arg[0]=rclsid REFCLSID — WASM ptr to 16-byte GUID
	// arg[1]=pUnkOuter — IUnknown* (NULL)
	// arg[2]=dwClsContext — scalar
	// arg[3]=riid REFIID — WASM ptr to 16-byte GUID
	// arg[4]=ppv — WASM ptr to output IUnknown* slot
	"CoCreateInstance": 1<<0 | 1<<3 | 1<<4, // 0x19

	// CoUninitialize() — no args
	"CoUninitialize": 0x00,
}

// getPointerMask returns the pointer bitmask for a Win32 API. It checks
// semantic overrides first (hand-curated for remote-memory APIs), then
// falls back to the auto-generated masks from win32metadata. If neither
// has an entry, ok is false and the caller should use the heuristic.
func getPointerMask(procName string) (uint32, bool) {
	// Semantic overrides take priority (hand-curated for correctness).
	if mask, ok := semanticOverrides[procName]; ok {
		return mask, true
	}
	// Fall back to auto-generated metadata masks.
	if mask, ok := generatedPointerMasks[procName]; ok {
		return mask, true
	}
	return 0, false
}

// win32Available returns 1 if Win32APIs are enabled in the config, 0 otherwise.
func win32Available(ctx context.Context, mod api.Module) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return 0
	}
	return 1
}

// win32LoadLibrary loads a DLL by name and writes a guest handle ID to handlePtr.
func win32LoadLibrary(ctx context.Context, mod api.Module, namePtr, nameLen, handlePtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	nameBytes, ok := readBytes(mod, namePtr, nameLen)
	if !ok {
		return errnoEFAULT
	}
	name := string(nameBytes)
	mirrorDebugLog("LoadLibrary: name=%s", name)

	handle, err := windows.LoadLibrary(name)
	if err != nil {
		return win32Errno(err)
	}

	id := ht.register(&win32HandleEntry{
		kind:      handleDLL,
		dllHandle: uintptr(handle),
	})

	if !writeInt32(mod, handlePtr, id) {
		windows.FreeLibrary(windows.Handle(handle))
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32GetProcAddress looks up a procedure address within a loaded DLL.
func win32GetProcAddress(ctx context.Context, mod api.Module, libHandle int32, namePtr, nameLen, procPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(libHandle)
	if entry == nil || entry.kind != handleDLL {
		return errnoEBADF
	}

	nameBytes, ok := readBytes(mod, namePtr, nameLen)
	if !ok {
		return errnoEFAULT
	}
	procName := string(nameBytes)
	mirrorDebugLog("GetProcAddress: lib=0x%x name=%s", libHandle, procName)

	addr, err := windows.GetProcAddress(windows.Handle(entry.dllHandle), procName)
	if err != nil {
		return win32Errno(err)
	}

	newEntry := &win32HandleEntry{
		kind:      handleProc,
		procAddr:  addr,
		debugName: procName,
	}
	// Look up known pointer mask for this API. When set, win32SyscallN
	// uses it instead of the heuristic to determine which args are WASM
	// pointers — critical for APIs with large integer args (sizes, remote
	// addresses) that the heuristic would incorrectly translate.
	if mask, ok := getPointerMask(procName); ok {
		newEntry.hasPointerMask = true
		newEntry.pointerMask = mask
		mirrorDebugLog("GetProcAddress: %s -> pointer mask 0x%x", procName, mask)
	}
	id := ht.register(newEntry)

	if !writeInt32(mod, procPtr, id) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32Call invokes a procedure address obtained via win32GetProcAddress.
// The args array in WASM memory contains nargs uint32 values; the return
// value is written to retPtr as a uint32.
func win32Call(ctx context.Context, mod api.Module, proc int32, nargs, argsPtr, retPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(proc)
	if entry == nil || entry.kind != handleProc {
		return errnoEBADF
	}

	if nargs > 6 {
		return errnoEINVAL
	}

	// Read up to 6 uint32 arguments from WASM memory.
	var args [6]uintptr
	for i := uint32(0); i < nargs; i++ {
		v, ok := readUint32(mod, argsPtr+i*4)
		if !ok {
			return errnoEFAULT
		}
		args[i] = uintptr(v)
	}

	// Translate WASM pointers to host addresses (same logic as win32SyscallN).
	if mem := mod.Memory(); mem != nil {
		memSize := mem.Size()
		if memSize > 0 {
			if buf, ok := mem.Read(0, 1); ok && len(buf) > 0 {
				base := uintptr(unsafe.Pointer(&buf[0]))
				const threshold = 0x10000
				var sizeOf [6]bool
				const maxSizeArg = 0x100000 // 1MB — legitimate buffer sizes rarely exceed this
				for i := uint32(0); i < nargs; i++ {
					v := uint32(args[i])
					if v >= threshold && v < memSize {
						if sizeOf[i] {
							continue
						}
						args[i] = base + uintptr(v)
						if i+1 < nargs {
							nextV := uint32(args[i+1])
							if nextV >= threshold && nextV < maxSizeArg &&
								uint64(v)+uint64(nextV) <= uint64(memSize) {
								sizeOf[i+1] = true
							}
						}
					}
				}
			}
		}
	}

	// Async-yield protocol for blocking APIs (matching win32SyscallN). Without
	// this, calls like WaitForSingleObject / Sleep made through Proc.Call()
	// stall the entire WASM scheduler. `retPtr` is the owner token here, the
	// same way `ret1Ptr` works in the SyscallN path.
	isBlocking := entry.debugName != "" && blockingAPIs[entry.debugName]
	if isBlocking {
		pendingAsync.mu.Lock()
		if pendingAsync.owner == retPtr && pendingAsync.owner != 0 {
			if pendingAsync.done {
				ret := pendingAsync.r1
				pendingAsync.owner = 0
				pendingAsync.done = false
				pendingAsync.mu.Unlock()
				if !writeUint32(mod, retPtr, uint32(ret)) {
					return errnoEFAULT
				}
				return errnoSuccess
			}
			pendingAsync.mu.Unlock()
			time.Sleep(time.Millisecond)
			return errnoYIELD
		}

		if pendingAsync.owner != 0 {
			// Another goroutine owns the slot; fall through to sync call.
			pendingAsync.mu.Unlock()
		} else {
			pendingAsync.owner = retPtr
			pendingAsync.done = false
			pendingAsync.mu.Unlock()

			asyncProc := entry.procAddr
			asyncArgs := args
			go func() {
				ar1, ar2, aerr := syscall.SyscallN(asyncProc,
					asyncArgs[0], asyncArgs[1], asyncArgs[2],
					asyncArgs[3], asyncArgs[4], asyncArgs[5])
				pendingAsync.mu.Lock()
				pendingAsync.r1 = ar1
				pendingAsync.r2 = ar2
				pendingAsync.err = aerr
				pendingAsync.done = true
				pendingAsync.mu.Unlock()
				_ = ar2
				_ = aerr
			}()
			return errnoYIELD
		}
	}

	ret, _, _ := syscall.SyscallN(entry.procAddr,
		args[0], args[1], args[2], args[3], args[4], args[5])

	if !writeUint32(mod, retPtr, uint32(ret)) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32FreeLibrary releases a loaded DLL handle.
func win32FreeLibrary(ctx context.Context, mod api.Module, handle int32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.remove(handle)
	if entry == nil || entry.kind != handleDLL {
		return errnoEBADF
	}

	if err := windows.FreeLibrary(windows.Handle(entry.dllHandle)); err != nil {
		return win32Errno(err)
	}
	return errnoSuccess
}

// comInitOnce ensures CoInitializeEx is called exactly once on the WASM
// execution thread. COM interfaces (used by CLR/.NET hosting) require an
// initialized apartment. Without this, some COM methods deadlock.
var comInitOnce sync.Once

// comProcs holds lazily-loaded Win32 function pointers for COM support.
var comProcs struct {
	once              sync.Once
	coInitializeEx    *syscall.Proc
	createEvent       *syscall.Proc
	setEvent          *syscall.Proc
	closeHandle       *syscall.Proc
	createThread      *syscall.Proc
	getExitCodeThread *syscall.Proc
	msgWait           *syscall.Proc
	peekMessage       *syscall.Proc
	translateMsg      *syscall.Proc
	dispatchMsg       *syscall.Proc
}

func loadComProcs() {
	comProcs.once.Do(func() {
		if ole32, err := syscall.LoadDLL("ole32.dll"); err == nil {
			comProcs.coInitializeEx, _ = ole32.FindProc("CoInitializeEx")
		}
		if kernel32, err := syscall.LoadDLL("kernel32.dll"); err == nil {
			comProcs.createEvent, _ = kernel32.FindProc("CreateEventW")
			comProcs.setEvent, _ = kernel32.FindProc("SetEvent")
			comProcs.closeHandle, _ = kernel32.FindProc("CloseHandle")
			comProcs.createThread, _ = kernel32.FindProc("CreateThread")
			comProcs.getExitCodeThread, _ = kernel32.FindProc("GetExitCodeThread")
		}
		if user32, err := syscall.LoadDLL("user32.dll"); err == nil {
			comProcs.msgWait, _ = user32.FindProc("MsgWaitForMultipleObjects")
			comProcs.peekMessage, _ = user32.FindProc("PeekMessageW")
			comProcs.translateMsg, _ = user32.FindProc("TranslateMessage")
			comProcs.dispatchMsg, _ = user32.FindProc("DispatchMessageW")
		}
	})
}

// initCOM calls CoInitializeEx(NULL, COINIT_MULTITHREADED) to set up the
// COM apartment on the current OS thread.
func initCOM() {
	loadComProcs()
	if comProcs.coInitializeEx != nil {
		// COINIT_MULTITHREADED = 0x0.
		comProcs.coInitializeEx.Call(0, 0)
	}
}

// comWorkerRequest represents a SyscallN call dispatched to the COM worker.
type comWorkerRequest struct {
	proc      uintptr
	args      []uintptr
	r1        uintptr
	r2        uintptr
	err       syscall.Errno
	doneEvent uintptr // Auto-reset event signaled when response is ready

	// workFn, when non-nil, is executed INSTEAD of SyscallN. Used for
	// complex COM operations (WMI queries) that need to run on the STA
	// worker thread but require more than a single syscall.
	workFn  func() (string, error)
	workStr string // Result from workFn
	workErr error  // Error from workFn
}

// blockingAPIs lists Win32 functions that may block for extended periods.
// These are dispatched to background goroutines instead of the COM worker
// to avoid freezing all WASM guest goroutines.
var blockingAPIs = map[string]bool{
	"WaitForSingleObject":         true,
	"WaitForSingleObjectEx":       true,
	"WaitForMultipleObjects":      true,
	"WaitForMultipleObjectsEx":    true,
	"Sleep":                       true,
	"SleepEx":                     true,
	"ReadFile":                    true,
	"WriteFile":                   true,
	"WaitNamedPipeW":              true,
	"ConnectNamedPipe":            true,
	"GetQueuedCompletionStatus":   true,
	"MsgWaitForMultipleObjects":   true,
	"MsgWaitForMultipleObjectsEx": true,
	"SignalObjectAndWait":         true,
	"GetExitCodeThread":           true,
}

// pendingAsyncState tracks a single in-flight async Win32 call.
// The owner field (ret1Ptr) uniquely identifies the guest goroutine.
// All fields are protected by mu — no atomic needed.
//
// ret1Ptr works as an owner token because WASM is single-threaded:
// each goroutine's SyscallN call frame has a unique stack-allocated
// ret1Buf, and cooperative scheduling means no two goroutines execute
// win32SyscallN concurrently. The same goroutine retrying gets the
// same ret1Ptr (same call frame), while a different goroutine gets
// a different stack address.
type pendingAsyncState struct {
	mu    sync.Mutex
	owner uint32 // ret1Ptr of the owning goroutine (0 = no pending)
	done  bool   // true when background goroutine has finished
	r1    uintptr
	r2    uintptr
	err   syscall.Errno
}

var pendingAsync pendingAsyncState

// comWorker is the persistent COM worker goroutine state.
var comWorker struct {
	once        sync.Once
	reqChan     chan *comWorkerRequest // Requests sent to the worker
	ready       chan struct{}          // Closed when worker is initialized
	vehCallback uintptr                // VEH callback pointer (prevent GC)
}

// comWorkerInit starts the persistent COM worker goroutine. Uses a Go goroutine
// with runtime.LockOSThread() (not a raw CreateThread) for full Go runtime
// support. The worker calls SetEvent directly after SyscallN — no goroutine
// bridge needed. This avoids both the raw-thread crash (v19) and the goroutine
// starvation (v17).
func comWorkerInit() {
	comWorker.reqChan = make(chan *comWorkerRequest, 1)
	comWorker.ready = make(chan struct{})

	loadComProcs()

	// Install a vectored exception handler to catch access violations
	// and other crashes in the COM worker before Windows terminates us.
	ntdll, _ := syscall.LoadDLL("ntdll.dll")
	if ntdll != nil {
		addVEH, _ := ntdll.FindProc("RtlAddVectoredExceptionHandler")
		if addVEH != nil {
			comWorker.vehCallback = syscall.NewCallback(comVectoredExceptionHandler)
			addVEH.Call(1, comWorker.vehCallback) // 1 = first handler
			mirrorDebugLog("comWorker: installed vectored exception handler")
		}
	}

	go func() {
		// Lock this goroutine to a dedicated OS thread for COM thread affinity.
		runtime.LockOSThread()
		// Never UnlockOSThread — this thread is dedicated to COM for the
		// process lifetime.

		mirrorDebugLog("comWorker: goroutine started on dedicated OS thread")

		// Initialize COM apartment on this thread with STA.
		// CLR COM objects (IEnumUnknown, ICLRRuntimeInfo) may require STA
		// for certain operations like EnumerateInstalledRuntimes::Next.
		if comProcs.coInitializeEx != nil {
			r, _, _ := comProcs.coInitializeEx.Call(0, 2) // COINIT_APARTMENTTHREADED = 0x2
			mirrorDebugLog("comWorker: CoInitializeEx(STA) returned 0x%x", r)
		}

		mirrorDebugLog("comWorker: ready for requests")
		close(comWorker.ready)

		// Process requests forever. This goroutine never returns.
		for req := range comWorker.reqChan {
			if req.workFn != nil {
				// Complex COM operation (e.g., WMI query) — run on STA thread.
				mirrorDebugLog("comWorker: executing workFn")
				req.workStr, req.workErr = req.workFn()
				mirrorDebugLog("comWorker: workFn returned len=%d err=%v", len(req.workStr), req.workErr)
			} else {
				mirrorDebugLog("comWorker: executing proc=0x%x nargs=%d args=[0x%x,0x%x,0x%x,0x%x,0x%x,0x%x]",
					req.proc, len(req.args),
					safeArg(req.args, 0), safeArg(req.args, 1), safeArg(req.args, 2),
					safeArg(req.args, 3), safeArg(req.args, 4), safeArg(req.args, 5))
				r1, r2, errno := syscall.SyscallN(req.proc, req.args...)
				mirrorDebugLog("comWorker: proc=0x%x returned r1=0x%x r2=0x%x err=%d", req.proc, r1, r2, errno)

				req.r1 = r1
				req.r2 = r2
				req.err = errno
			}

			// Signal the caller directly via Windows event. No goroutine
			// bridge — this goroutine is on its own OS thread and can call
			// SetEvent immediately after SyscallN returns.
			if comProcs.setEvent != nil && req.doneEvent != 0 {
				comProcs.setEvent.Call(req.doneEvent)
			}
		}
	}()
}

func safeArg(args []uintptr, i int) uintptr {
	if i < len(args) {
		return args[i]
	}
	return 0
}

// comVectoredExceptionHandler is called by Windows before any SEH handler
// when an exception occurs. It logs the exception so we can diagnose crashes
// in COM calls. Returns EXCEPTION_CONTINUE_SEARCH (0) to let normal handling proceed.
func comVectoredExceptionHandler(exceptionInfo uintptr) uintptr {
	// EXCEPTION_POINTERS layout:
	//   [0]  EXCEPTION_RECORD*
	//   [8]  CONTEXT*
	//
	// EXCEPTION_RECORD layout (x64):
	//   [0]  DWORD  ExceptionCode
	//   [4]  DWORD  ExceptionFlags
	//   [8]  EXCEPTION_RECORD* ExceptionRecord (chained)
	//   [16] PVOID  ExceptionAddress
	//   [24] DWORD  NumberParameters
	//   [28] 4 bytes padding
	//   [32] ULONG_PTR ExceptionInformation[0] (read=0/write=1/DEP=8)
	//   [40] ULONG_PTR ExceptionInformation[1] (faulting address)
	type exceptionPointers struct {
		exceptionRecord uintptr
		contextRecord   uintptr
	}
	type exceptionRecord struct {
		code      uint32
		flags     uint32
		record    uintptr
		address   uintptr
		numParams uint32
		_pad      uint32
		info0     uintptr // Read(0)/Write(1)/DEP(8)
		info1     uintptr // Faulting virtual address
	}

	ptrs := (*exceptionPointers)(unsafe.Pointer(exceptionInfo))
	if ptrs != nil && ptrs.exceptionRecord != 0 {
		rec := (*exceptionRecord)(unsafe.Pointer(ptrs.exceptionRecord))
		if rec != nil {
			code := rec.code
			if code == 0xC0000005 {
				rwStr := "READ"
				if rec.info0 == 1 {
					rwStr = "WRITE"
				} else if rec.info0 == 8 {
					rwStr = "DEP"
				}
				mirrorDebugLog("VEH: ACCESS_VIOLATION at 0x%x: %s of 0x%x (flags=0x%x numParams=%d)",
					rec.address, rwStr, rec.info1, rec.flags, rec.numParams)
			} else if code == 0xC00000FD || code == 0xC0000374 ||
				code == 0xC0000409 || code == 0x80000003 {
				mirrorDebugLog("VEH: exception code=0x%x addr=0x%x flags=0x%x",
					code, rec.address, rec.flags)
			}
		}
	}
	return 0 // EXCEPTION_CONTINUE_SEARCH
}

// comSyscallNWithMsgPump dispatches a SyscallN call to the persistent COM
// worker goroutine and waits for completion.
//
// Design:
//   - Worker: Go goroutine + LockOSThread + CoInitializeEx/STA (full Go runtime)
//   - Request delivery: Go channel (worker blocks on channel recv)
//   - Completion signal: Worker calls SetEvent directly (no goroutine bridge)
//   - Caller waits: WaitForSingleObject on auto-reset event (simple, reliable)
func comSyscallNWithMsgPump(proc uintptr, args []uintptr) (uintptr, uintptr, syscall.Errno) {
	comWorker.once.Do(comWorkerInit)
	<-comWorker.ready

	if comWorker.reqChan == nil {
		mirrorDebugLog("comSyscallNWithMsgPump: no worker, direct call proc=0x%x", proc)
		r1, r2, err := syscall.SyscallN(proc, args...)
		return r1, r2, err
	}

	loadComProcs()

	// Create an auto-reset event for completion signaling.
	var doneEvent uintptr
	if comProcs.createEvent != nil {
		doneEvent, _, _ = comProcs.createEvent.Call(0, 0, 0, 0) // bManualReset=0
	}

	req := &comWorkerRequest{
		proc:      proc,
		args:      args,
		doneEvent: doneEvent,
	}

	mirrorDebugLog("comSyscallNWithMsgPump: dispatching proc=0x%x nargs=%d event=0x%x", proc, len(args), doneEvent)
	comWorker.reqChan <- req
	mirrorDebugLog("comSyscallNWithMsgPump: request sent to worker channel")

	// Wait for the worker to complete using WaitForSingleObject.
	// MsgWaitForMultipleObjects was unreliable from the wazero execution
	// context (never returned, not even on timeout). WaitForSingleObject
	// is simpler and more reliable.
	if doneEvent != 0 {
		kernel32, _ := syscall.LoadDLL("kernel32.dll")
		wfso, _ := kernel32.FindProc("WaitForSingleObject")
		if wfso != nil {
			// Poll with short waits instead of a single 120s wait. A long
			// WaitForSingleObject from a wazero-hosting goroutine pins
			// the OS thread past Go runtime's safe-point window, causing
			// `exitsyscall: syscall frame is no longer valid` panic when
			// the runtime later compacts stacks while the goroutine is
			// still blocked in the kernel. Short waits return periodically
			// and let the runtime treat each wait as a normal blocking
			// syscall it can manage.
			mirrorDebugLog("comSyscallNWithMsgPump: polling WaitForSingleObject event=0x%x", doneEvent)
			const pollIntervalMs = 100
			const maxPollIterations = 1200 // 120s total
			var r uintptr
			done := false
			for i := 0; i < maxPollIterations; i++ {
				r, _, _ = wfso.Call(doneEvent, pollIntervalMs)
				if r == 0 { // WAIT_OBJECT_0
					done = true
					break
				}
				if r != 258 { // anything other than WAIT_TIMEOUT is an error
					break
				}
				// Yield to Go runtime so it can run other goroutines and
				// reach safe points. Without this, the OS thread is hot
				// in WFSO and the runtime accumulates pending work.
				runtime.Gosched()
			}
			mirrorDebugLog("comSyscallNWithMsgPump: poll loop exit r=0x%x done=%v", r, done)
			if !done {
				comProcs.closeHandle.Call(doneEvent)
				if r == 258 {
					return 0, 0, syscall.Errno(0x800705B4) // ERROR_TIMEOUT
				}
				return 0, 0, syscall.Errno(r)
			}
		}
		comProcs.closeHandle.Call(doneEvent)
	}

	mirrorDebugLog("comSyscallNWithMsgPump: completed proc=0x%x r1=0x%x err=%d", proc, req.r1, req.err)
	return req.r1, req.r2, req.err
}

// ComRunOnSTA dispatches an arbitrary function to the COM STA worker thread
// and waits for completion. Used for complex COM operations (like WMI queries)
// that need STA apartment threading but require more than a single SyscallN.
func ComRunOnSTA(fn func() (string, error)) (string, error) {
	comWorker.once.Do(comWorkerInit)
	<-comWorker.ready

	if comWorker.reqChan == nil {
		// No worker available — run directly (may fail if STA required)
		return fn()
	}

	loadComProcs()

	var doneEvent uintptr
	if comProcs.createEvent != nil {
		doneEvent, _, _ = comProcs.createEvent.Call(0, 0, 0, 0)
	}

	req := &comWorkerRequest{
		workFn:    fn,
		doneEvent: doneEvent,
	}

	comWorker.reqChan <- req

	if doneEvent != 0 {
		kernel32, _ := syscall.LoadDLL("kernel32.dll")
		wfso, _ := kernel32.FindProc("WaitForSingleObject")
		if wfso != nil {
			r, _, _ := wfso.Call(doneEvent, 120000)
			if r == 258 { // WAIT_TIMEOUT
				comProcs.closeHandle.Call(doneEvent)
				return "", fmt.Errorf("ComRunOnSTA: timeout (120s)")
			}
		}
		comProcs.closeHandle.Call(doneEvent)
	}

	return req.workStr, req.workErr
}

// win32SyscallN calls a procedure with up to 15 int64-width arguments.
// argsPtr points to an array of nargs int64 values in WASM memory (nargs*8 bytes).
// On success, ret1Ptr, ret2Ptr, and lastErrPtr each receive an int64 written
// as little-endian 8 bytes, matching the Windows SyscallN convention.
//
// Shadow memory support:
//   - VirtualAlloc/VirtualProtect/VirtualFree calls through SyscallN are
//     intercepted and redirected to shadow allocation (WASM + host memory).
//   - If proc points into shadow memory (native code entry point from COFF/BOF
//     loading), all shadow regions are synced and the native code is executed.
//   - For regular calls, shadow pointer arguments are translated transparently.
func win32SyscallN(ctx context.Context, mod api.Module, proc int32, nargs int32, argsPtr, ret1Ptr, ret2Ptr, lastErrPtr uint32) uint32 {
	mirrorDebugLog("SyscallN-ENTRY: proc=%d nargs=%d", proc, nargs)
	// Initialize COM apartment on first call (idempotent).
	comInitOnce.Do(initCOM)
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}

	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoENOSYS
	}

	if nargs < 0 || nargs > 15 {
		return errnoEINVAL
	}

	sm := getShadowMap(ctx)
	mt := getMirrorTable(ctx)
	isShadowEntryPoint := false

	entry := ht.get(proc)
	if entry == nil || entry.kind != handleProc {
		// Check if proc is a shadow address — a native code entry point
		// in shadow-allocated memory (e.g., from a COFF/BOF loader that
		// VirtualAlloc'd memory and loaded object code into it).
		if sm != nil {
			if se := sm.LookupContaining(uint32(proc)); se != nil {
				offset := uintptr(uint32(proc)) - uintptr(se.wasmAddr)
				entry = &win32HandleEntry{
					kind:     handleProc,
					procAddr: se.hostAddr + offset,
				}
				isShadowEntryPoint = true
			}
		}
		// Check mirror table for COM vtable method pointers.
		// When guest code calls syscall.Syscall(mirroredMethodAddr, ...),
		// the proc is a WASM mirror address pointing to DLL code. Reverse-
		// translate it to the original host function address.
		if entry == nil && mt != nil {
			if me := mt.LookupByWasm(uint32(proc)); me != nil {
				offset := uint32(proc) - me.wasmAddr
				entry = &win32HandleEntry{
					kind:     handleProc,
					procAddr: me.hostAddr + uintptr(offset),
				}
				mirrorDebugLog("ProcResolve: mirror wasm=0x%x -> host=0x%x (entry.wasm=0x%x offset=%d)",
					uint32(proc), entry.procAddr, me.wasmAddr, offset)
			} else if hostAddr, ok := mt.LookupPendingByWasm(uint32(proc)); ok {
				// Pending mirror proc: the host function address is known but
				// hasn't been copied into WASM memory yet. This happens when
				// a COM vtable entry was registered as pending and the guest
				// calls through it before reading the data.
				entry = &win32HandleEntry{
					kind:     handleProc,
					procAddr: hostAddr,
				}
				mirrorDebugLog("ProcResolve: pending mirror wasm=0x%x -> host=0x%x",
					uint32(proc), hostAddr)
			}
		}
		// Truncated proc recovery: CLR CCW (COM Callable Wrapper) vtable
		// entries are 48-bit host addresses (e.g., 0x21b73a315c2) that
		// the i32 wasmimport ABI truncates to 32 bits (0x73a315c2).
		// ScanAndMirrorPointers records code-region pointers in a
		// truncation map during vtable scanning, keyed by the low 32
		// bits. This recovers the full 64-bit address for dispatch.
		if entry == nil && mt != nil {
			if fullAddr, ok := mt.LookupTruncatedProc(uint32(proc)); ok {
				entry = &win32HandleEntry{
					kind:     handleProc,
					procAddr: fullAddr,
				}
				mirrorDebugLog("ProcResolve: truncated-proc-recovery proc=0x%x -> host=0x%x",
					uint32(proc), fullAddr)
			}
		}
		// Truncated address linear scan: when the truncation map doesn't
		// have a match, scan all mirrored host addresses for one whose
		// low 32 bits match the proc value. This handles CLR CCW vtable
		// entries that the scanner saw but didn't individually mirror
		// (e.g., due to dedup refresh or depth/budget limits).
		// O(n) over byHost, but only fires as a last resort.
		if entry == nil && mt != nil {
			uProc := uint32(proc)
			mt.mu.RLock()
			for _, me := range mt.byHost {
				if uint32(me.hostAddr) == uProc && me.hostAddr != uintptr(uProc) {
					entry = &win32HandleEntry{
						kind:     handleProc,
						procAddr: me.hostAddr,
					}
					mirrorDebugLog("ProcResolve: byHost-scan proc=0x%x -> host=0x%x (low32 match)",
						uProc, me.hostAddr)
					break
				}
			}
			mt.mu.RUnlock()
		}
		if entry == nil {
			// Read args to help diagnose which COM method the guest is trying to call.
			var diagArgs []uintptr
			if nargs > 0 {
				if diagBytes, ok := readBytes(mod, argsPtr, uint32(nargs)*8); ok {
					diagArgs = make([]uintptr, nargs)
					for j := int32(0); j < nargs; j++ {
						diagArgs[j] = uintptr(binary.LittleEndian.Uint64(diagBytes[j*8 : (j+1)*8]))
					}
				}
			}
			// Diagnostic: dump mirror table sizes and lookup attempts to
			// understand why proc resolution failed.
			truncMapSize, byWasmSize, pendingSize := 0, 0, 0
			if mt != nil {
				mt.mu.RLock()
				truncMapSize = len(mt.truncatedProcs)
				byWasmSize = len(mt.byWasm)
				pendingSize = len(mt.pending)
				mt.mu.RUnlock()
			}
			mirrorDebugLog("ProcResolve: FAILED proc=0x%x (not in handle table, shadow, or mirror) nargs=%d args=%v truncMap=%d byWasm=%d pending=%d",
				uint32(proc), nargs, diagArgs, truncMapSize, byWasmSize, pendingSize)
			return errnoEBADF
		}
	}

	// Read args from WASM memory (array of int64, 8 bytes each).
	args := make([]uintptr, nargs)
	preTranslateArgs := make([]uint32, nargs) // Original WASM values for post-call scanning.
	if nargs > 0 {
		argBytes, ok := readBytes(mod, argsPtr, uint32(nargs)*8)
		if !ok {
			return errnoEFAULT
		}
		for i := int32(0); i < nargs; i++ {
			val := binary.LittleEndian.Uint64(argBytes[i*8 : (i+1)*8])
			args[i] = uintptr(val)
			preTranslateArgs[i] = uint32(val)
		}
	}

	// Step 0: Mirror reverse translation — if an arg is a mirror WASM
	// address, replace it with the original host address so the native API
	// receives the real pointer.
	//
	// IMPORTANT: Do NOT call SyncToHost here. ScanAndMirrorPointers replaces
	// host pointers in the WASM mirror copy with WASM mirror addresses (for
	// guest readability). Syncing that data back to the host would overwrite
	// the original host pointers in the COM object with WASM addresses,
	// causing access violations when the native COM method dereferences them.
	mirrorTranslated := make([]bool, nargs) // Track which args were mirror-translated.
	if mt != nil {
		for i := int32(0); i < nargs; i++ {
			if entry := mt.LookupByWasm(uint32(args[i])); entry != nil {
				offset := uintptr(uint32(args[i])) - uintptr(entry.wasmAddr)
				args[i] = entry.hostAddr + offset
				mirrorTranslated[i] = true
				if i == 0 {
					mirrorDebugLog("Step0: proc mirror-translated wasm=0x%x -> host=0x%x",
						uint32(preTranslateArgs[i]), args[i])
				}
			} else if hostAddr, ok := mt.LookupPendingByWasm(uint32(args[i])); ok {
				// Pending mirror: not yet copied into WASM, but we know the
				// host address. Translate directly so the native call gets the
				// real pointer (the guest doesn't need the data — it's passing
				// the address through to another API call).
				args[i] = hostAddr
				mirrorTranslated[i] = true
				mirrorDebugLog("Step0: pending mirror-translated wasm=0x%x -> host=0x%x",
					uint32(preTranslateArgs[i]), hostAddr)
			}
		}
	}
	// Intercept VirtualAlloc/VirtualProtect/VirtualFree for automatic
	// shadow allocation. This allows code that calls these through raw
	// SyscallN (like goffloader) to get WASM-accessible addresses.
	if sm != nil && !isShadowEntryPoint {
		if handled, errno := interceptShadowMemoryCall(mod, sm, entry.procAddr, nargs, args, ret1Ptr, ret2Ptr, lastErrPtr); handled {
			return errno
		}
	}

	// Shadow entry point: full sync before/after native code execution.
	if isShadowEntryPoint && sm != nil {
		return execShadowEntryPoint(mod, sm, ht, entry.procAddr, nargs, args, ret1Ptr, ret2Ptr, lastErrPtr)
	}

	// Shadow memory translation: detect shadow pointers in args,
	// pre-sync WASM→Host, and translate addresses.
	type touchedEntry struct {
		wasmAddr uint32
		hostAddr uintptr
		size     uint32
	}
	var touched []touchedEntry
	seen := make(map[uint32]bool)

	if sm != nil {
		for i := int32(0); i < nargs; i++ {
			wasmVal := uint32(args[i])
			se := sm.LookupContaining(wasmVal)
			if se == nil {
				continue
			}
			// Pre-sync this shadow region (once per unique allocation).
			if !seen[se.wasmAddr] {
				seen[se.wasmAddr] = true
				wasmData, ok := readBytes(mod, se.wasmAddr, se.size)
				if !ok {
					return errnoEFAULT
				}
				hostSlice := unsafeSlice(se.hostAddr, se.size)
				copy(hostSlice, wasmData)
				touched = append(touched, touchedEntry{
					wasmAddr: se.wasmAddr,
					hostAddr: se.hostAddr,
					size:     se.size,
				})
			}
			// Translate: WASM addr → Host addr (preserving offset within allocation).
			offset := uintptr(wasmVal - se.wasmAddr)
			args[i] = se.hostAddr + offset
		}
	}

	// Pipe FD → Windows handle translation: when a Win32 API receives a
	// WasmForge pipe FD (>= 15000), translate it to the real OS file handle.
	// This is critical for SetStdHandle, which expects a real Windows HANDLE,
	// not a WasmForge-internal pipe FD. Without this, CLR stdout/stderr
	// redirection fails because the handle is invalid.
	pt := getPipeTable(ctx)
	if pt != nil {
		for i := int32(0); i < nargs; i++ {
			val := uint32(args[i])
			if isPipeFD(val) {
				if h := pt.nativeHandle(int32(val)); h != 0 {
					args[i] = h
					mirrorDebugLog("PipeFD: arg[%d] pipe FD %d -> Windows handle 0x%x", i, val, h)
				}
			}
		}
	}

	// WASM linear memory pointer translation: any argument that looks like
	// a WASM linear memory address (within bounds) is translated to the
	// corresponding host address. This enables Win32 APIs that take pointer
	// args (e.g., GetUserDefaultLocaleName, CreateFileW) to read/write
	// directly to/from the WASM guest's memory.
	//
	// wazero's Memory.Read returns a subslice of the backing Buffer, so
	// &Buffer[offset] is a valid host pointer for the duration of the call.
	mem := mod.Memory()
	var wasmMemBase uintptr
	var wasmMemSize uint32
	if mem != nil {
		wasmMemSize = mem.Size()
		if wasmMemSize > 0 {
			// Read 1 byte at offset 0 to get a slice pointing into the buffer.
			if buf, ok := mem.Read(0, 1); ok && len(buf) > 0 {
				wasmMemBase = uintptr(unsafe.Pointer(&buf[0]))
			}
		}
	}
	if wasmMemBase != 0 {
		// Threshold: WASM addresses for Go programs are above the first 64KB
		// (data/BSS/heap start well above 0x10000). Values below this are
		// likely scalar constants, flags, sizes, or predefined handles.
		const wasmPtrThreshold = 0x10000

		// Pointer mask mode: if the proc has a known pointer mask, use it
		// to determine exactly which args are WASM pointers. This avoids
		// the heuristic's false positives for large integers (sizes, remote
		// addresses) that fall in the WASM memory range.
		if entry.hasPointerMask {
			for i := int32(0); i < nargs; i++ {
				if entry.pointerMask&(1<<uint(i)) == 0 {
					continue // Not a pointer per mask — skip translation.
				}
				wasmVal := uint32(args[i])
				if wasmVal < wasmPtrThreshold || wasmVal >= wasmMemSize {
					continue // Outside WASM memory range — no translation needed.
				}
				if seen[wasmVal] || mirrorTranslated[i] || args[i] != uintptr(wasmVal) {
					continue // Already translated by prior step.
				}
				args[i] = wasmMemBase + uintptr(wasmVal)
				mirrorDebugLog("Step3-mask: arg[%d] WASM 0x%x -> host 0x%x (mask=0x%x, proc=%s)",
					i, wasmVal, args[i], entry.pointerMask, entry.debugName)
			}
		} else {
			// Heuristic mode: for APIs without a known pointer mask, translate
			// any arg in the WASM memory range as a pointer. This works for
			// most APIs but can misidentify large sizes or remote addresses.

			// sizeOf tracks args identified as buffer sizes (not pointers).
			var sizeOf [15]bool
			for i := int32(0); i < nargs; i++ {
				wasmVal := uint32(args[i])
				if wasmVal >= wasmPtrThreshold && wasmVal < wasmMemSize {
					// Already translated by shadow memory? Skip.
					if seen[wasmVal] {
						continue
					}
					// Already translated by mirror reverse translation? Skip.
					if mirrorTranslated[i] {
						continue
					}
					// Check if this was already translated (arg changed from original).
					if args[i] != uintptr(wasmVal) {
						continue
					}
					// Buffer-size heuristic: if this arg was identified as a
					// buffer size for a preceding pointer arg, don't translate it.
					// The (ptr, size) pattern is ubiquitous in Win32 APIs.
					if sizeOf[i] {
						continue
					}
					args[i] = wasmMemBase + uintptr(wasmVal)
					// Buffer-size heuristic: if arg[i+1] looks like a buffer
					// size rather than a pointer, don't translate it. We check:
					// 1. arg[i] + arg[i+1] fits within WASM memory (size of buffer)
					// 2. arg[i+1] < 16MB (no legitimate size arg is that large,
					//    but WASM heap pointers in Go programs are typically > 16MB)
					const maxSizeArg = 0x100000 // 1MB — legitimate buffer sizes rarely exceed this
					if i+1 < nargs {
						nextVal := uint32(args[i+1])
						if nextVal >= wasmPtrThreshold && nextVal < maxSizeArg &&
							uint64(wasmVal)+uint64(nextVal) <= uint64(wasmMemSize) {
							sizeOf[i+1] = true
						}
					}
				}
			}
		} // end else (heuristic mode)
	}

	// Step 3.5: Deep mirror translation — scan arg-pointed WASM memory for
	// embedded mirror addresses (4-byte wasm32 pointers) and temporarily
	// widen them to 8-byte host addresses in the host buffer. This handles
	// data structures like VARIANTs that embed SAFEARRAY mirror pointers.
	//
	// Problem: Guest code constructs a VARIANT containing a SAFEARRAY mirror
	// address (e.g., 0x111d5b0). Step 3 translates the pointer TO the VARIANT
	// (wasmMemBase + offset), but the 4-byte mirror address INSIDE the VARIANT
	// is not translated. The native x64 code reads 8 bytes at offset 8 of the
	// VARIANT, getting the 4-byte mirror address zero-extended to 64 bits —
	// an unmapped address that causes ACCESS_VIOLATION.
	//
	// Fix: For each Step 3-translated arg, scan the first 128 bytes of the
	// pointed-to host buffer for 4-byte values matching known mirror entries.
	// Replace each match with the 8-byte host address. Restore after the call.
	type deepMirrorPatch struct {
		hostAddr uintptr // Host buffer address where we patched
		original [8]byte // Original 8 bytes to restore
	}
	var deepMirrorPatches []deepMirrorPatch

	if mt != nil && wasmMemBase != 0 {
		for i := int32(0); i < nargs; i++ {
			origWasm := preTranslateArgs[i]
			// Only scan args that were WASM linear memory pointers (translated by Step 3).
			if origWasm < 0x10000 || origWasm >= wasmMemSize {
				continue
			}
			// Skip mirror-translated and shadow-translated args.
			if mirrorTranslated[i] || seen[origWasm] {
				continue
			}
			// Skip data buffer args: if the NEXT arg looks like a buffer
			// size for this pointer, this arg is a raw data pointer (e.g.,
			// RtlCopyMemory src, WriteFile buffer). Scanning raw data for
			// mirror addresses causes false positives — e.g., MZ header bytes
			// 4D5A9000 as little-endian uint32 = 0x00905a4d can collide with
			// mirror addresses, corrupting the first bytes of the buffer.
			if i+1 < nargs {
				nextVal := uint32(preTranslateArgs[i+1])
				if nextVal >= 0x10000 && nextVal < 0x100000 &&
					uint64(origWasm)+uint64(nextVal) <= uint64(wasmMemSize) {
					continue
				}
			}
			// Scan up to 32 bytes for embedded mirror addresses.
			// Keep small to avoid false positives from adjacent heap data.
			// VARIANT (the primary target) has the pointer at offset 8;
			// 32 bytes covers all common COM parameter structs.
			scanSize := uint32(32)
			if origWasm+scanSize > wasmMemSize {
				scanSize = wasmMemSize - origWasm
			}
			if scanSize < 4 {
				continue
			}
			hostBufAddr := wasmMemBase + uintptr(origWasm)
			hostBuf := unsafe.Slice((*byte)(unsafe.Pointer(hostBufAddr)), scanSize)

			for off := uint32(0); off+4 <= scanSize; off += 4 {
				val := uint32(hostBuf[off]) | uint32(hostBuf[off+1])<<8 |
					uint32(hostBuf[off+2])<<16 | uint32(hostBuf[off+3])<<24
				if val < 0x10000 || val >= wasmMemSize {
					continue
				}
				me := mt.LookupByWasm(val)
				if me == nil {
					continue
				}
				// Found an embedded mirror address. Replace the 4-byte value
				// with the 8-byte host address (widening from wasm32 to x64).
				hostTarget := me.hostAddr + uintptr(val-me.wasmAddr)

				// Save original 8 bytes for restoration. If fewer than 8 bytes
				// remain, save what we can (and skip patching if < 8 to avoid OOB).
				if off+8 > scanSize {
					continue
				}
				var orig [8]byte
				copy(orig[:], hostBuf[off:off+8])
				// Write 8-byte host address.
				binary.LittleEndian.PutUint64(hostBuf[off:off+8], uint64(hostTarget))

				deepMirrorPatches = append(deepMirrorPatches, deepMirrorPatch{
					hostAddr: hostBufAddr + uintptr(off),
					original: orig,
				})
				mirrorDebugLog("Step3.5: deep mirror arg[%d]+%d wasm=0x%x -> host=0x%x",
					i, off, val, hostTarget)
				// Skip ahead 8 bytes since we wrote an 8-byte value.
				off += 4 // +4 here, +4 from loop increment = 8 total
			}
		}
	}

	if cfg.Verbose {
		fmt.Printf("[runtime] SyscallN: %s (proc=0x%x, nargs=%d, args=[", entry.debugName, entry.procAddr, nargs)
		for i := int32(0); i < nargs && i < 4; i++ {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("0x%x", args[i])
		}
		if nargs > 4 {
			fmt.Printf(", ...+%d more", nargs-4)
		}
		fmt.Println("])")
	}

	// Only log unnamed procs (COM vtable calls) to keep debug log manageable.
	if entry.debugName == "" {
		// Log all args for COM calls to diagnose vtable dispatch issues.
		argStrs := make([]string, nargs)
		for i := int32(0); i < nargs; i++ {
			argStrs[i] = fmt.Sprintf("0x%x", args[i])
		}
		mirrorDebugLog("SyscallN: proc=0x%x nargs=%d args=[%s]",
			entry.procAddr, nargs, strings.Join(argStrs, ", "))
	}
	// Route all SyscallN calls through the COM worker goroutine when active.
	// This ensures COM thread affinity: CLRCreateInstance AND subsequent COM
	// vtable calls all execute on the same OS thread (the worker). Without
	// this, CLRCreateInstance runs on the main thread, creating COM objects
	// there. Later COM vtable calls on the worker thread would need cross-
	// thread marshaling, which blocks because the CLR expects same-thread
	// access for IEnumUnknown::Next and similar methods.
	// Pre-sync writable mirrors: copy guest-written data (e.g., .NET assembly
	// bytes in SafeArray pvData) from WASM back to host memory. Must happen
	// after all arg translation (Steps 0-3) and before the native call.
	if mt != nil {
		mt.SyncWritableMirrors(mod)
	}

	var r1, r2 uintptr
	var err syscall.Errno

	isBlocking := entry.debugName != "" && blockingAPIs[entry.debugName]

	if isBlocking {
		pendingAsync.mu.Lock()
		if pendingAsync.owner == ret1Ptr && pendingAsync.owner != 0 {
			// Retry from same goroutine — check if done.
			if pendingAsync.done {
				r1 = pendingAsync.r1
				r2 = pendingAsync.r2
				err = pendingAsync.err
				pendingAsync.owner = 0
				pendingAsync.done = false
				pendingAsync.mu.Unlock()

				// r1/r2/err are now set. Jump to post-call cleanup which
				// handles deep mirror undo, Step 6/7, and writeReturnValues.
				mirrorDebugLog("SyscallN-ASYNC-DONE: %s r1=0x%x err=%d", entry.debugName, r1, err)

				goto postCall
			}
			// Not done yet — throttled yield to prevent CPU spin.
			// Without this sleep, the guest retry loop spins at millions of
			// iterations/sec burning 100% CPU while waiting for the background
			// goroutine to complete (e.g., Sleep, WaitForSingleObject).
			pendingAsync.mu.Unlock()
			time.Sleep(time.Millisecond)
			mirrorDebugLog("SyscallN-ASYNC-YIELD: %s still pending", entry.debugName)
			return errnoYIELD
		}

		if pendingAsync.owner != 0 {
			// Another goroutine has a pending async — can't start a new one.
			// Fall through to synchronous path.
			pendingAsync.mu.Unlock()
			mirrorDebugLog("SyscallN-ASYNC-BUSY: %s, falling back to sync", entry.debugName)
		} else {
			// Start new async operation.
			pendingAsync.owner = ret1Ptr
			pendingAsync.done = false
			pendingAsync.mu.Unlock()

			// Capture args for the background goroutine.
			asyncProc := entry.procAddr
			asyncArgs := make([]uintptr, len(args))
			copy(asyncArgs, args)
			asyncName := entry.debugName

			go func() {
				ar1, ar2, aerr := syscall.SyscallN(asyncProc, asyncArgs...)
				pendingAsync.mu.Lock()
				pendingAsync.r1 = ar1
				pendingAsync.r2 = ar2
				pendingAsync.err = aerr
				pendingAsync.done = true
				pendingAsync.mu.Unlock()
				mirrorDebugLog("SyscallN-ASYNC-BG: %s completed r1=0x%x err=%d", asyncName, ar1, aerr)
			}()

			mirrorDebugLog("SyscallN-ASYNC-START: %s dispatched to background", entry.debugName)
			return errnoYIELD
		}
	}

	// Synchronous path (non-blocking APIs or fallback).
	r1, r2, err = comSyscallNWithMsgPump(entry.procAddr, args)
	if entry.debugName == "" {
		mirrorDebugLog("SyscallN: returned r1=0x%x r2=0x%x err=%d",
			r1, r2, err)
		// For COM calls, dump each output arg's raw value immediately
		// after the native call (before deep mirror undo / Step 6).
		// This reveals what the native COM method actually wrote.
		for i := int32(0); i < nargs; i++ {
			origWasm := preTranslateArgs[i]
			if origWasm >= 0x10000 && origWasm < uint32(wasmMemSize) {
				if !seen[origWasm] && !mirrorTranslated[i] {
					if raw, ok := readBytes(mod, origWasm, 8); ok {
						rawVal := le64(raw)
						mirrorDebugLog("SyscallN: COM output-diag arg[%d] wasm=0x%x rawVal=0x%x", i, origWasm, rawVal)
					}
				}
			}
		}
	}

postCall:
	// Undo deep mirror patches: restore original bytes in the host buffer
	// so WASM guest code sees its original mirror addresses. Must happen
	// after the native call completes but before any WASM code resumes.
	for _, p := range deepMirrorPatches {
		dst := unsafe.Slice((*byte)(unsafe.Pointer(p.hostAddr)), 8)
		copy(dst, p.original[:])
	}

	// Post-refresh writable mirrors: copy host data back to WASM for any
	// writable mirrors that may have been modified by the native call.
	// This handles the case where the guest passes a mirror address through
	// SyscallN (e.g., RtlCopyMemory(pvData_mirror, src, len)) — Step 0
	// translates the mirror to the host address, so the native function
	// writes to host memory. Without this refresh, the WASM mirror would
	// still have stale data, and the next SyncWritableMirrors would
	// overwrite the host with stale zeros.
	if mt != nil {
		mt.RefreshWritableMirrors(mod)
	}

	// Post-sync: copy Host → WASM for all touched shadow regions.
	for _, t := range touched {
		hostSlice := unsafeSlice(t.hostAddr, t.size)
		hostData := make([]byte, t.size)
		copy(hostData, hostSlice)
		if !writeBytes(mod, t.wasmAddr, hostData) {
			return errnoEFAULT
		}
	}

	// Step 6: Lazy host pointer registration in output parameters.
	//
	// After the native call, scan output parameters for host pointers that
	// the guest needs to dereference (COM interfaces, heap-allocated structs).
	// Never mirror r1 (handles, HRESULTs — always opaque).
	//
	// Instead of eagerly copying host data into WASM memory, we register a
	// "pending mirror" — a WASM address beyond current memory that will
	// trigger the memory fault handler when the guest accesses it. The
	// handler then grows memory, copies data on demand, and resumes.
	if mt != nil && wasmMemBase != 0 {
		for i := int32(0); i < nargs; i++ {
			// If we have a pointer mask, only scan args that the mask
			// identifies as WASM pointers. Without this check, non-pointer
			// args (e.g., remote process addresses passed to NtQueryVirtualMemory
			// or NtReadVirtualMemory) that happen to fall in the WASM range
			// cause Step 6 to read/write unrelated WASM memory, corrupting
			// global state.
			if entry != nil && entry.hasPointerMask && entry.pointerMask&(1<<uint(i)) == 0 {
				mirrorDebugLog("Step6: SKIP arg[%d] reason=pointer_mask_not_set (mask=0x%x proc=%s)", i, entry.pointerMask, entry.debugName)
				continue
			}
			// Skip Step 6 mirror scanning for Nt API output buffers that contain
			// target-process addresses or raw memory, not host pointers.
			if noMirror, ok := ntAPINoMirrorArgs[entry.debugName]; ok && noMirror&(1<<uint(i)) != 0 {
				mirrorDebugLog("Step6: SKIP arg[%d] reason=nt_api_no_mirror (proc=%s)", i, entry.debugName)
				continue
			}
			origWasm := preTranslateArgs[i]
			// Only check args that were WASM pointers (translated in Step 3).
			if origWasm < 0x10000 || origWasm >= wasmMemSize {
				if entry.debugName == "" {
					mirrorDebugLog("Step6: SKIP arg[%d] origWasm=0x%x reason=range (threshold=0x10000 memSize=0x%x)", i, origWasm, wasmMemSize)
				}
				continue
			}
			// Skip shadow-translated and mirror-translated args.
			if seen[origWasm] || mirrorTranslated[i] {
				if entry.debugName == "" {
					mirrorDebugLog("Step6: SKIP arg[%d] origWasm=0x%x reason=already_translated (seen=%v mirror=%v)", i, origWasm, seen[origWasm], mirrorTranslated[i])
				}
				continue
			}

			// Read the 8-byte value at this WASM location (what the native
			// function wrote to the output parameter).
			valBytes, ok := readBytes(mod, origWasm, 8)
			if !ok {
				mirrorDebugLog("Step6: SKIP arg[%d] origWasm=0x%x reason=readBytes_failed", i, origWasm)
				continue
			}
			val := le64(valBytes)
			mirrorDebugLog("Step6: arg[%d] origWasm=0x%x val=0x%x (memSize=0x%x wasmMemBase=0x%x proc=%s)", i, origWasm, val, wasmMemSize, wasmMemBase, entry.debugName)
			if val == 0 {
				mirrorDebugLog("Step6: SKIP arg[%d] reason=val_zero", i)
				continue
			}
			// NOTE: We intentionally do NOT filter by val <= wasmMemSize here.
			// On 64-bit Windows, host heap addresses can be in the low 4GB range,
			// overlapping with WASM offset values. The host buffer range check
			// at line ~1268 correctly handles WASM-internal pointers.
			if val < 0x10000 {
				mirrorDebugLog("Step6: SKIP arg[%d] reason=val_below_threshold (val=0x%x)", i, val)
				continue
			}
			// Skip values outside reasonable user-mode address range.
			if val > 0x7FFFFFFFFFFF {
				mirrorDebugLog("Step6: SKIP arg[%d] reason=val_above_usermode (val=0x%x)", i, val)
				continue
			}
			// Skip values that point back into WASM linear memory's host buffer.
			// When Win32 APIs write pointers into a translated WASM buffer (Step 3),
			// those pointers are host addresses within wazero's backing array, NOT
			// external host objects. The guest passes them as-is to subsequent
			// SyscallN calls where they work correctly without translation.
			// Example: GetTokenInformation writes TOKEN_OWNER.Owner pointing into
			// the same buffer — it's wasmMemBase+offset, not a COM interface.
			if val >= uint64(wasmMemBase) && val < uint64(wasmMemBase)+uint64(wasmMemSize) {
				mirrorDebugLog("Step6: SKIP arg[%d] reason=val_in_wasm_host_buffer (val=0x%x base=0x%x end=0x%x)", i, val, wasmMemBase, uint64(wasmMemBase)+uint64(wasmMemSize))
				continue
			}

			hostPtr := uintptr(val)

			// Already mirrored eagerly? Return existing mirror address.
			// But first validate offset 0: the original recursive scan may have
			// left a raw host vtable pointer if mirrorReadHost failed (Pattern B:
			// CLR CCW thunk not yet committed) or a UTF-16-corrupted mirror
			// (Pattern A: CLR GC reused the thunk heap). By the time Step 6 runs,
			// the native API has returned and the CLR has initialized the COM
			// object, so re-reading now should succeed.
			if existing := mt.LookupByHost(hostPtr); existing != nil {
				mirrorDebugLog("Step6: DEDUP arg[%d] host=0x%x -> existing wasm=0x%x", i, hostPtr, existing.wasmAddr)
				// Validate mirror data quality. WASM is 32-bit, so any
				// 8-byte value with upper bits set (> 0xFFFFFFFF) is a raw
				// 64-bit host address, not a valid WASM address. This catches
				// Pattern A (UTF-16 strings: 0x0041004C...), Pattern B (raw
				// CCW thunks: 0x1ee1a8e8f80), and Pattern B2 (raw function
				// pointers inside a mirrored vtable).
				needsRescan := false
				if existing.size >= 8 {
					if chkData, chkOk := readBytes(mod, existing.wasmAddr, 8); chkOk {
						val0 := le64(chkData)
						if val0 == 0 {
							// Offset 0 is NULL — no valid COM object has a
							// NULL vtable pointer. This mirror was pre-populated
							// before the CLR initialized the object.
							needsRescan = true
							mirrorDebugLog("Step6: DEDUP stale offset0=NULL wasm=0x%x", existing.wasmAddr)
						} else if val0 > 0xFFFFFFFF {
							// Offset 0 is a raw 64-bit host address.
							needsRescan = true
							mirrorDebugLog("Step6: DEDUP stale offset0=0x%x (>32bit) wasm=0x%x", val0, existing.wasmAddr)
						} else if val0 > 0x10000 {
							// Offset 0 is a 32-bit value — could be a valid WASM mirror.
							// Check vtable data for stale entries (raw host addresses).
							vtEntry := mt.LookupByWasm(uint32(val0))
							if vtEntry != nil {
								vtData, vtOk := readBytes(mod, vtEntry.wasmAddr, min(vtEntry.size, 56))
								if vtOk {
									for j := 0; j+8 <= len(vtData); j += 8 {
										if le64(vtData[j:j+8]) > 0xFFFFFFFF {
											// Vtable entry has raw 64-bit address. Invalidate
											// the vtable mirror so re-scan does a full copy.
											mt.mu.Lock()
											delete(mt.byWasm, vtEntry.wasmAddr)
											delete(mt.byHost, vtEntry.hostAddr)
											mt.mu.Unlock()
											needsRescan = true
											mirrorDebugLog("Step6: DEDUP stale vtable entry at off=%d wasm=0x%x", j, vtEntry.wasmAddr)
											break
										}
									}
								}
							}
						}
					}
				}
				if needsRescan {
					mirrorDebugLog("Step6: DEDUP rescan host=0x%x wasm=0x%x", hostPtr, existing.wasmAddr)
					// Retry loop: for NULL vtable (CLR not yet initialized),
					// re-read with increasing delays. COM objects returned by
					// QueryInterface must have a valid vtable — if offset 0 is
					// still NULL, the CLR is still initializing the object.
					for retryAttempt := 0; retryAttempt < 8; retryAttempt++ {
						if retryAttempt > 0 {
							delays := []int{0, 15, 30, 50, 80, 100, 150, 200} // total ~625ms
							delay := time.Duration(delays[retryAttempt]) * time.Millisecond
							time.Sleep(delay)
							mirrorDebugLog("Step6: DEDUP retry %d after %v host=0x%x", retryAttempt, delay, hostPtr)
						}
						hostData := mirrorReadHost(hostPtr, existing.size)
						if hostData == nil {
							continue
						}
						writeBytes(mod, existing.wasmAddr, hostData)
						freshData, freshOk := readBytes(mod, existing.wasmAddr, existing.size)
						if freshOk {
							budget := 500
							mt.ScanAndMirrorPointers(mod, existing.wasmAddr, freshData, wasmMemSize, maxMirrorDepth, &budget, make(map[uintptr]bool))
							mirrorDebugLog("Step6: DEDUP re-scanned wasm=0x%x budget_used=%d attempt=%d", existing.wasmAddr, 500-budget, retryAttempt)
						}
						// Check if offset 0 is now valid.
						if len(hostData) >= 8 && le64(hostData[:8]) != 0 {
							break // Vtable pointer is non-NULL — done.
						}
					}
				}
				putLE64(valBytes, uint64(existing.wasmAddr))
				writeBytes(mod, origWasm, valBytes)
				continue
			}

			// VirtualQuery validation: only register committed, non-image memory.
			// MEM_IMAGE means it's a loaded DLL/EXE — those are opaque handles.
			if !mirrorShouldMirror(hostPtr) {
				mirrorDebugLog("Step6: mirrorShouldMirror REJECTED host=0x%x", hostPtr)
				continue
			}

			// Determine region size for the pending mirror.
			// For COM method output parameters (unnamed procs), use a
			// small region. COM objects are typically just a vtable
			// pointer (8 bytes) plus a few instance fields. Mirroring
			// 4096 bytes of the surrounding heap captures hundreds of
			// CLR internal pointers that waste the mirror scan budget.
			// Named Win32 APIs (like CLRCreateInstance) may write
			// larger structures, so keep 4096 for those.
			regionSize := mirrorRegionSize(hostPtr)
			if regionSize == 0 {
				regionSize = 8192
			}
			if entry.debugName == "" {
				// COM method: small region (vtable ptr + instance fields).
				if regionSize > 64 {
					regionSize = 64
				}
			} else {
				if regionSize > 8192 {
					regionSize = 8192
				}
			}

			// Register as a pending mirror. If the address falls beyond
			// current WASM memory, the guest's first read triggers the
			// memory fault handler which grows and copies. But if a
			// previous HandleFault already grew memory past the arena
			// cursor, the new address may already be in-bounds — in
			// that case, eagerly populate to avoid the guest reading
			// uninitialized zeros (which causes nil vtable crashes
			// for COM interfaces like IEnumUnknown).
			pendingAddr := mt.RegisterPending(mod, hostPtr, regionSize, wasmMemSize)
			if pendingAddr == 0 {
				continue
			}

			// Replace the host pointer in WASM with the pending mirror address.
			putLE64(valBytes, uint64(pendingAddr))
			writeBytes(mod, origWasm, valBytes)
			mirrorDebugLog("Step6: registered pending mirror host=0x%x -> wasm=0x%x arg=%d regionSize=%d proc=%s",
				hostPtr, pendingAddr, i, regionSize, entry.debugName)
			mirrorDiag("Step6: REGISTER host=0x%x -> pending=0x%x arg=%d regionSize=%d proc=%s",
				hostPtr, pendingAddr, i, regionSize, entry.debugName)

			// Always eagerly resolve: grow memory and populate immediately.
			// The lazy path (guest OOB access → OS signal → HandleFault)
			// has catastrophic overhead on Windows (~100-250 SECONDS per
			// fault due to structured exception handling + Memory.Grow
			// inside a signal handler). Eager resolution runs Memory.Grow
			// from normal Go code, avoiding the signal path entirely.
			currentMemSize := uint32(mod.Memory().Size())
			if pendingAddr+regionSize > currentMemSize {
				pagesNeeded := uint32((uint64(pendingAddr) + uint64(regionSize) - uint64(currentMemSize) + 65535) / 65536)
				if _, ok := mod.Memory().Grow(pagesNeeded); ok {
					currentMemSize = uint32(mod.Memory().Size())
					mirrorDebugLog("Step6: grew memory by %d pages for eager resolve (new memSize=0x%x)",
						pagesNeeded, currentMemSize)
				} else {
					mirrorDebugLog("Step6: memory grow FAILED (need %d pages, current=0x%x) — pending=0x%x will fault",
						pagesNeeded, currentMemSize, pendingAddr)
				}
			}
			if pendingAddr+regionSize <= currentMemSize {
				mirrorDebugLog("Step6: eager-resolving pending=0x%x memSize=0x%x host=0x%x proc=%s",
					pendingAddr, currentMemSize, hostPtr, entry.debugName)
				mirrorDiag("Step6: EAGER-RESOLVE pending=0x%x memSize=0x%x host=0x%x proc=%s",
					pendingAddr, currentMemSize, hostPtr, entry.debugName)
				mt.ResolvePendingEager(mod, pendingAddr, currentMemSize)
			}
		}
	}

	// Post-Step 6 diagnostic: for COM calls, confirm what each output arg
	// looks like after mirroring. Shows pending/mirror addresses or 0 if
	// Step 6 didn't write anything (helps diagnose pAssembly=0 issues).
	if mt != nil && wasmMemBase != 0 && entry.debugName == "" {
		for i := int32(0); i < nargs; i++ {
			origWasm := preTranslateArgs[i]
			if origWasm >= 0x10000 && origWasm < uint32(wasmMemSize) {
				if !seen[origWasm] && !mirrorTranslated[i] {
					if final, ok := readBytes(mod, origWasm, 8); ok {
						finalVal := le64(final)
						mirrorDebugLog("Step6-FINAL: arg[%d] wasm=0x%x finalVal=0x%x", i, origWasm, finalVal)
					}
				}
			}
		}
	}

	// Post-Step 6 NULL vtable detection: for COM calls, check each mirrored
	// output arg for NULL offset 0 (uninitialized COM object). Log diagnostics
	// visible in test output to help trace the failure path.
	if mt != nil && wasmMemBase != 0 && entry.debugName == "" {
		for i := int32(0); i < nargs; i++ {
			origWasm := preTranslateArgs[i]
			if origWasm == 0 || origWasm < 0x10000 || origWasm >= uint32(wasmMemSize) {
				continue
			}
			if valBytes8, ok := readBytes(mod, origWasm, 8); ok {
				mirrorAddr := le64(valBytes8)
				if mirrorAddr > 0x10000 && mirrorAddr < uint64(wasmMemSize)*2 {
					// If beyond current WASM memory, grow and eagerly resolve.
					currentMS := uint32(mod.Memory().Size())
					if uint32(mirrorAddr)+64 > currentMS {
						needed := uint64(mirrorAddr) + 64
						pagesNeeded := uint32((needed - uint64(currentMS) + 65535) / 65536)
						if _, ok3 := mod.Memory().Grow(pagesNeeded); ok3 {
							currentMS = uint32(mod.Memory().Size())
							wasmMemSize = currentMS
							mt.ResolvePendingEager(mod, uint32(mirrorAddr), currentMS)
						}
					}
					// This arg points to a mirrored COM object. Check offset 0.
					if obj8, ok2 := readBytes(mod, uint32(mirrorAddr), 8); ok2 {
						vtPtr := le64(obj8)
						if vtPtr == 0 {
							// NULL vtable! Log diagnostics.
							hostEntry := mt.LookupByWasm(uint32(mirrorAddr))
							hostAddr := uintptr(0)
							if hostEntry != nil {
								hostAddr = hostEntry.hostAddr
							}
							// Also check pending mirrors.
							if hostAddr == 0 {
								if pendingHost, ok3 := mt.LookupPendingByWasm(uint32(mirrorAddr)); ok3 {
									hostAddr = pendingHost
								}
							}
							mirrorDiag("NULL_VT arg[%d] wasm=0x%x mirrorWasm=0x%x hostAddr=0x%x",
								i, origWasm, uint32(mirrorAddr), hostAddr)
							// Last-resort retry: one more mirrorReadHost with a
							// longer delay. If the CLR finally initialized, write
							// the data and re-scan.
							if hostAddr != 0 {
								time.Sleep(50 * time.Millisecond)
								lastChance := mirrorReadHost(hostAddr, 64)
								if lastChance != nil {
									lcVt := le64(lastChance[:8])
									mirrorDiag("LASTCHANCE host=0x%x vtPtr=0x%x", hostAddr, lcVt)
									if lcVt != 0 {
										writeBytes(mod, uint32(mirrorAddr), lastChance)
										budget := 500
										mt.ScanAndMirrorPointers(mod, uint32(mirrorAddr), lastChance, wasmMemSize, maxMirrorDepth, &budget, make(map[uintptr]bool))
										mirrorDiag("LASTCHANCE fixed wasm=0x%x budget_used=%d", uint32(mirrorAddr), 500-budget)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Step 6.5: Struct layout compaction for APIs that write pointer-containing
	// structs into output buffers. The native x64 call wrote x64-layout data
	// (8-byte pointers) into WASM memory, but the wasm32 guest expects 4-byte
	// pointers. Compact in-place before the guest resumes.
	if err == 0 && wasmMemBase != 0 {
		switch entry.debugName {
		case "GetTokenInformation":
			if nargs >= 5 {
				infoClass := preTranslateArgs[1]
				bufAddr := preTranslateArgs[2]
				// preTranslateArgs[3] = bufLen, [4] = &returnedLen
				// Read the actual bytes written from the ReturnLength output param.
				var dataLen uint32
				if retLenAddr := preTranslateArgs[4]; retLenAddr != 0 {
					if b, ok := readBytes(mod, retLenAddr, 4); ok {
						dataLen = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
					}
				}
				if dataLen == 0 {
					dataLen = preTranslateArgs[3] // fallback to bufLen
				}
				if dataLen > 0 && bufAddr != 0 {
					compactTokenInfoInPlace(mod.Memory(), bufAddr, infoClass, dataLen, wasmMemBase)
				}
			}

		case "NtQuerySystemInformation":
			// Fix ImageName.Buffer pointers in SYSTEM_PROCESS_INFORMATION linked list
			// from host addresses (wasmMemBase + offset) to WASM offsets.
			// Only applies to SystemProcessInformation (class 5).
			const systemProcessInformation = 5
			if nargs >= 4 && preTranslateArgs[0] == systemProcessInformation {
				bufAddr := preTranslateArgs[1]
				// Read actual data length from ReturnLength output param (arg[3]).
				var dataLen uint32
				if retLenAddr := preTranslateArgs[3]; retLenAddr != 0 {
					if b, ok := readBytes(mod, retLenAddr, 4); ok {
						dataLen = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
					}
				}
				if dataLen == 0 {
					dataLen = preTranslateArgs[2] // fallback to bufSize
				}
				if dataLen > 0 && bufAddr != 0 {
					fixNtQuerySystemInfoPointers(mod.Memory(), bufAddr, dataLen, wasmMemBase)
				}
			}
		}
	}

	// Step 7: Selective r1 mirroring for return values.
	//
	// Most Win32 APIs return opaque handles in r1 (LoadLibrary → HMODULE,
	// WinHttpOpen → HINTERNET) that must NOT be mirrored. A small set of
	// functions return dereferenceable heap pointers that the guest reads:
	//   - SafeArrayCreate → SAFEARRAY* (COM interop)
	//   - Unnamed COM vtable methods (entry.debugName == "")
	// Only mirror r1 for these cases.
	step7Eligible := entry.debugName == "" || entry.debugName == "SafeArrayCreate" ||
		entry.debugName == "SafeArrayCreateVector"
	// Check if r1 is within the WASM linear memory host buffer.
	// We compare against the host buffer range (wasmMemBase..wasmMemBase+wasmMemSize),
	// NOT the offset range (0..wasmMemSize). On 64-bit Windows, host heap addresses
	// from COM/OLE APIs can be in the low 4GB range, overlapping numerically with
	// WASM offsets. The old check (r1 > wasmMemSize) would incorrectly skip mirroring
	// when the WASM memory grew past the host address.
	r1InWasmBuffer := r1 >= wasmMemBase && r1 < wasmMemBase+uintptr(wasmMemSize)
	if mt != nil && step7Eligible && !r1InWasmBuffer && r1 > 0x10000 && r1 < 0x7FFFFFFFFFFF {
		if mirrorShouldMirror(r1) {
			// SafeArrayCreate returns a small struct (~32 bytes on x64).
			// Use exact struct size to avoid scanning heap noise.
			// For unnamed COM methods, use standard region sizing.
			var regionSize uint32
			isSafeArray := entry.debugName == "SafeArrayCreate" || entry.debugName == "SafeArrayCreateVector"
			if isSafeArray {
				regionSize = 64 // SAFEARRAY struct + rgsabound array with room
			} else {
				regionSize = mirrorRegionSize(r1)
				if regionSize == 0 {
					regionSize = 8192
				}
				if regionSize > 8192 {
					regionSize = 8192
				}
			}
			mirrorAddr := mt.Mirror(mod, r1, regionSize)
			if mirrorAddr != 0 {
				// Refresh in case of dedup.
				if refreshEntry := mt.LookupByHost(r1); refreshEntry != nil {
					if hostData := mirrorReadHost(r1, refreshEntry.size); hostData != nil {
						writeBytes(mod, refreshEntry.wasmAddr, hostData)
					}
				}
				mirrorDebugLog("Step7: mirrored r1 host=0x%x -> wasm=0x%x regionSize=%d proc=%s",
					r1, mirrorAddr, regionSize, entry.debugName)
				// For SafeArrayCreate, only mirror pvData pointer (offset 12, 8 bytes).
				// Don't do a full recursive scan — the SAFEARRAY fields are mostly
				// small integers and the data area is written later via SafeArrayAccessData.
				if isSafeArray {
					mirrorData, ok := readBytes(mod, mirrorAddr, regionSize)
					if ok && len(mirrorData) >= 20 {
						mirrorDebugLog("Step7: SAFEARRAY raw bytes: %x", mirrorData[:min(len(mirrorData), 32)])
						cDims := uint16(mirrorData[0]) | uint16(mirrorData[1])<<8
						fFeatures := uint16(mirrorData[2]) | uint16(mirrorData[3])<<8
						cbElements := uint32(mirrorData[4]) | uint32(mirrorData[5])<<8 | uint32(mirrorData[6])<<16 | uint32(mirrorData[7])<<24
						cLocks := uint32(mirrorData[8]) | uint32(mirrorData[9])<<8 | uint32(mirrorData[10])<<16 | uint32(mirrorData[11])<<24
						mirrorDebugLog("Step7: SAFEARRAY cDims=%d fFeatures=0x%x cbElements=%d cLocks=%d", cDims, fFeatures, cbElements, cLocks)
						// pvData is at offset 16 on x64 (cDims:2 + fFeatures:2 + cbElements:4 + cLocks:4 + padding:4 = 16, 8-byte aligned)
						if len(mirrorData) < 32 {
							mirrorDebugLog("Step7: SAFEARRAY too small for pvData")
						} else {
							pvData := le64(mirrorData[16:24])
							mirrorDebugLog("Step7: SAFEARRAY pvData=0x%x", pvData)
							pvDataInWasm := pvData >= uint64(wasmMemBase) && pvData < uint64(wasmMemBase)+uint64(wasmMemSize)
							if !pvDataInWasm && pvData > 0x10000 && pvData < 0x7FFFFFFFFFFF {
								hostPvData := uintptr(pvData)
								if mirrorShouldMirror(hostPvData) {
									// Mirror the data area. Size = cbElements * rgsabound[0].cElements
									// rgsabound at offset 24: cElements(4) + lLbound(4)
									var cElements uint32
									if len(mirrorData) >= 32 {
										cElements = uint32(mirrorData[24]) | uint32(mirrorData[25])<<8 |
											uint32(mirrorData[26])<<16 | uint32(mirrorData[27])<<24
									}
									dataSize := cbElements * cElements
									if dataSize == 0 {
										dataSize = 4096
									}
									// No size cap — .NET assemblies can be hundreds of KB.
									// Seatbelt.exe = 597KB, Rubeus.exe = 463KB.
									mirrorDebugLog("Step7: SAFEARRAY pvData mirror size=%d (cbElements=%d cElements=%d)", dataSize, cbElements, cElements)
									pvDataMirror := mt.MirrorWritable(mod, hostPvData, dataSize)
									if pvDataMirror != 0 {
										mirrorDebugLog("Step7: SAFEARRAY pvData host=0x%x -> wasm=0x%x size=%d",
											hostPvData, pvDataMirror, dataSize)
										// Replace pvData in the mirrored SAFEARRAY.
										putLE64(mirrorData[16:24], uint64(pvDataMirror))
										writeBytes(mod, mirrorAddr, mirrorData)
									}
								} else {
									mirrorDebugLog("Step7: SAFEARRAY pvData mirrorShouldMirror REJECTED 0x%x", hostPvData)
								}
							} else {
								mirrorDebugLog("Step7: SAFEARRAY pvData=0x%x outside range (wasmMemSize=0x%x)", pvData, wasmMemSize)
							}
						} // end else (len >= 32)
					}
				} else {
					mirrorData, ok := readBytes(mod, mirrorAddr, regionSize)
					if ok {
						budget := 50
						mt.ScanAndMirrorPointers(mod, mirrorAddr, mirrorData, wasmMemSize, maxMirrorDepth, &budget, make(map[uintptr]bool))
						mirrorDebugLog("Step7: scan complete budget_used=%d", 50-budget)
					}
				}
				r1 = uintptr(mirrorAddr)
			}
		}
	}

	rv := writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, r1, r2, uintptr(err))
	if entry != nil && (entry.debugName == "CertOpenSystemStoreW" || entry.debugName == "CertOpenStore" || entry.debugName == "CertEnumCertificatesInStore") {
		mirrorDebugLog("SyscallN-RETURN-DIAG: proc=%s r1=0x%x r2=0x%x err=%d ret1Ptr=0x%x",
			entry.debugName, r1, r2, err, ret1Ptr)
		verifyBuf, vok := readBytes(mod, ret1Ptr, 8)
		if vok {
			verifyR1 := le64(verifyBuf)
			mirrorDebugLog("SyscallN-VERIFY-DIAG: proc=%s readback=0x%x match=%v",
				entry.debugName, verifyR1, verifyR1 == uint64(r1))
		}
	}
	if entry != nil && (entry.debugName == "SafeArrayCreate" || entry.debugName == "SafeArrayCreateVector") {
		mirrorDebugLog("SyscallN-RETURN: r1=0x%x ret1Ptr=0x%x rv=%d proc=%s", r1, ret1Ptr, rv, entry.debugName)
		// Verify the write: read back r1 from the guest location.
		verifyBuf, vok := readBytes(mod, ret1Ptr, 8)
		if vok {
			verifyR1 := le64(verifyBuf)
			mirrorDebugLog("SyscallN-VERIFY: read back 0x%x at ret1Ptr=0x%x (expected 0x%x) match=%v",
				verifyR1, ret1Ptr, uint64(r1), verifyR1 == uint64(r1))
		} else {
			mirrorDebugLog("SyscallN-VERIFY: readBytes FAILED at ret1Ptr=0x%x", ret1Ptr)
		}
	}
	return rv
}

// unsafeSlice creates a byte slice from a host address and length.
func unsafeSlice(addr uintptr, size uint32) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
}

// --- Shadow Memory Interception ---
//
// When the WASM guest calls SyscallN with a proc handle pointing to
// kernel32's VirtualAlloc, VirtualProtect, or VirtualFree, we intercept
// the call and redirect to shadow allocation. This allocates in both
// WASM linear memory (via Memory.Grow) and real host memory (real
// VirtualAlloc), allowing guest code to use unsafe.Pointer on the returned
// address while the host has a synchronized copy for native API calls.

var (
	knownAddrVirtualAlloc   uintptr
	knownAddrVirtualProtect uintptr
	knownAddrVirtualFree    uintptr
	knownAddrsOnce          sync.Once
)

func initKnownProcAddrs() {
	knownAddrsOnce.Do(func() {
		k32, err := windows.LoadLibrary("kernel32.dll")
		if err != nil {
			return
		}
		// Don't free kernel32 — it stays loaded for the process lifetime.
		knownAddrVirtualAlloc, _ = windows.GetProcAddress(k32, "VirtualAlloc")
		knownAddrVirtualProtect, _ = windows.GetProcAddress(k32, "VirtualProtect")
		knownAddrVirtualFree, _ = windows.GetProcAddress(k32, "VirtualFree")
	})
}

// writeReturnValues writes r1, r2, and lastErr to the guest's return buffers
// in the SyscallN convention (little-endian int64 each).
func writeReturnValues(mod api.Module, ret1Ptr, ret2Ptr, lastErrPtr uint32, r1, r2 uintptr, lastErr uintptr) uint32 {
	var buf [8]byte

	binary.LittleEndian.PutUint64(buf[:], uint64(r1))
	if !writeBytes(mod, ret1Ptr, buf[:]) {
		return errnoEFAULT
	}

	binary.LittleEndian.PutUint64(buf[:], uint64(r2))
	if !writeBytes(mod, ret2Ptr, buf[:]) {
		return errnoEFAULT
	}

	binary.LittleEndian.PutUint64(buf[:], uint64(lastErr))
	if !writeBytes(mod, lastErrPtr, buf[:]) {
		return errnoEFAULT
	}

	return errnoSuccess
}

// interceptShadowMemoryCall checks if procAddr matches a known memory
// management function (VirtualAlloc/VirtualProtect/VirtualFree) and
// intercepts the call for shadow allocation. Returns (true, errno) if
// the call was intercepted, or (false, 0) to fall through.
func interceptShadowMemoryCall(mod api.Module, sm *shadowMap, procAddr uintptr, nargs int32, args []uintptr, ret1Ptr, ret2Ptr, lastErrPtr uint32) (bool, uint32) {
	initKnownProcAddrs()

	if knownAddrVirtualAlloc != 0 && procAddr == knownAddrVirtualAlloc {
		return true, interceptVirtualAlloc(mod, sm, nargs, args, ret1Ptr, ret2Ptr, lastErrPtr)
	}
	if knownAddrVirtualProtect != 0 && procAddr == knownAddrVirtualProtect {
		return true, interceptVirtualProtect(mod, sm, nargs, args, ret1Ptr, ret2Ptr, lastErrPtr)
	}
	if knownAddrVirtualFree != 0 && procAddr == knownAddrVirtualFree {
		return true, interceptVirtualFree(mod, sm, nargs, args, ret1Ptr, ret2Ptr, lastErrPtr)
	}

	return false, 0
}

// --- Shadow Arena ---
//
// The shadow arena reserves a large contiguous block of host virtual address
// space (MEM_RESERVE, no physical memory) that mirrors the WASM memory growth
// region. Individual shadow allocations COMMIT pages within this arena at
// offsets matching their WASM addresses relative to the first shadow allocation.
//
// This is critical for COFF/BOF loading: the guest's relocation processing
// computes relative offsets between sections using WASM addresses. By keeping
// the same relative distances in the host arena, those offsets remain valid
// when native code executes at host addresses.
//
// Layout:
//   WASM:  [program memory...][shadow_0][gap?][shadow_1][gap?][shadow_2]...
//   Host:  [arena_base       + offset_0      + offset_1      + offset_2...]
//   where offset_N = shadow_N.wasmAddr - arena.wasmBase

const (
	shadowArenaSize = 4 * 1024 * 1024 * 1024 // 4GB — covers full 32-bit WASM address space

	// maxGuestHandleID is the upper bound for the GOT fixup heuristic.
	// Guest handle IDs start at win32BaseHandle (20000) and increment.
	// Native x64 addresses are always >> 1M, so any 8-byte value in
	// [win32BaseHandle, maxGuestHandleID) is treated as a handle ID.
	maxGuestHandleID = 0x100000
)

type shadowArenaState struct {
	once     sync.Once
	initErr  error
	hostBase atomic.Uintptr // Start of reserved host region (MEM_RESERVE)
	wasmBase atomic.Uint32  // WASM address of first shadow allocation (set once)
}

var shadowArena shadowArenaState

// initShadowArena reserves the host arena on first use.
func initShadowArena() error {
	shadowArena.once.Do(func() {
		addr, err := windows.VirtualAlloc(0, shadowArenaSize, windows.MEM_RESERVE, windows.PAGE_NOACCESS)
		if err != nil {
			shadowArena.initErr = fmt.Errorf("shadow arena reserve: %w", err)
			return
		}
		shadowArena.hostBase.Store(uintptr(addr))
	})
	return shadowArena.initErr
}

// arenaHostAddr computes the host address for a given WASM shadow address.
// Safe to call concurrently after initShadowArena succeeds.
func arenaHostAddr(wasmAddr uint32) uintptr {
	return shadowArena.hostBase.Load() + uintptr(wasmAddr-shadowArena.wasmBase.Load())
}

// interceptVirtualAlloc handles VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect).
// Grows WASM linear memory and commits pages in the host arena at the matching offset.
// Returns the WASM address to the guest, which is usable with unsafe.Pointer.
func interceptVirtualAlloc(mod api.Module, sm *shadowMap, nargs int32, args []uintptr, ret1Ptr, ret2Ptr, lastErrPtr uint32) uint32 {
	if nargs < 4 {
		return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, 0, 0, 87) // ERROR_INVALID_PARAMETER
	}

	// lpAddress = args[0] (ignored — we always let OS choose for both host and WASM).
	size := uint32(args[1])
	allocType := uint32(args[2])
	protect := uint32(args[3])

	if size == 0 {
		return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, 0, 0, 87)
	}

	// Ensure host arena is reserved.
	if err := initShadowArena(); err != nil {
		return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, 0, 0, 8) // ERROR_NOT_ENOUGH_MEMORY
	}

	// Grow WASM linear memory to create space for the shadow copy.
	// Pages are 64KB each. The new memory is at [prevPages*64K, (prevPages+pages)*64K).
	pages := (size + 65535) / 65536
	prevPages, ok := mod.Memory().Grow(pages)
	if !ok {
		return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, 0, 0, 8)
	}
	wasmAddr := prevPages * 65536

	// Record the WASM base on first allocation (atomic CAS — only first wins).
	shadowArena.wasmBase.CompareAndSwap(0, wasmAddr)

	// Commit host pages at the corresponding arena offset.
	// Use MEM_COMMIT (not allocType) since the arena is already MEM_RESERVE'd.
	hostAddr := arenaHostAddr(wasmAddr)
	_, err := windows.VirtualAlloc(hostAddr, uintptr(size), windows.MEM_COMMIT, protect)
	if err != nil {
		// Arena commit failed — try standalone allocation as fallback.
		// NOTE: This breaks the relative-offset invariant between allocations,
		// so RIP-relative relocations in native COFF code may fail. This is a
		// last-resort path; the arena should succeed for normal use cases.
		hostAddr, err = windows.VirtualAlloc(0, uintptr(size), allocType, protect)
		if err != nil {
			return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, 0, 0, uintptr(win32Errno(err)))
		}
	}

	// Register shadow mapping.
	sm.Register(wasmAddr, hostAddr, size, protect)

	return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, uintptr(wasmAddr), 0, 0)
}

// interceptVirtualProtect handles VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect).
// Pre-syncs WASM→Host, calls real VirtualProtect on the host memory, and writes
// the old protection value to the WASM pointer at lpflOldProtect.
func interceptVirtualProtect(mod api.Module, sm *shadowMap, nargs int32, args []uintptr, ret1Ptr, ret2Ptr, lastErrPtr uint32) uint32 {
	if nargs < 4 {
		return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, 0, 0, 87)
	}

	wasmAddr := uint32(args[0])
	size := uint32(args[1])
	newProtect := uint32(args[2])
	oldProtectWasmPtr := uint32(args[3]) // WASM pointer to write old protection

	entry := sm.LookupContaining(wasmAddr)
	if entry == nil {
		// Not a shadow address — call the real VirtualProtect directly.
		r1, r2, err := syscall.SyscallN(knownAddrVirtualProtect, args...)
		return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, r1, r2, uintptr(err))
	}

	// Pre-sync: temporarily make host memory writable, then copy WASM → Host.
	var tmpOldProtect uint32
	if entry.protect != uint32(windows.PAGE_READWRITE) && entry.protect != uint32(windows.PAGE_EXECUTE_READWRITE) {
		windows.VirtualProtect(entry.hostAddr, uintptr(entry.size), windows.PAGE_READWRITE, &tmpOldProtect)
	}

	wasmData, ok := readBytes(mod, entry.wasmAddr, entry.size)
	if !ok {
		return errnoEFAULT
	}
	hostSlice := unsafeSlice(entry.hostAddr, entry.size)
	copy(hostSlice, wasmData)

	// Call real VirtualProtect on the translated host address.
	hostTargetAddr := entry.hostAddr + uintptr(wasmAddr-entry.wasmAddr)
	var oldProtect uint32
	if err := windows.VirtualProtect(hostTargetAddr, uintptr(size), newProtect, &oldProtect); err != nil {
		return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, 0, 0, uintptr(win32Errno(err)))
	}

	// Write the tracked old protection to WASM memory. Use entry.protect
	// (what the guest last set) rather than oldProtect (which may reflect
	// our temporary PAGE_READWRITE).
	if oldProtectWasmPtr != 0 {
		writeUint32(mod, oldProtectWasmPtr, entry.protect)
	}

	// Update the shadow entry's protection.
	sm.UpdateProtect(entry.wasmAddr, newProtect)

	return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, 1, 0, 0) // BOOL TRUE
}

// interceptVirtualFree handles VirtualFree(lpAddress, dwSize, dwFreeType).
// Removes the shadow mapping and decommits the host arena pages.
func interceptVirtualFree(mod api.Module, sm *shadowMap, nargs int32, args []uintptr, ret1Ptr, ret2Ptr, lastErrPtr uint32) uint32 {
	if nargs < 3 {
		return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, 0, 0, 87)
	}

	wasmAddr := uint32(args[0])

	entry := sm.Remove(wasmAddr)
	if entry == nil {
		// Not a shadow address — call the real VirtualFree.
		r1, r2, err := syscall.SyscallN(knownAddrVirtualFree, args...)
		return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, r1, r2, uintptr(err))
	}

	// Decommit the pages (host arena pages are COMMIT'd within a RESERVE'd region).
	// MEM_DECOMMIT releases the physical pages but keeps the address range reserved.
	// If this entry is outside the arena (fallback allocation), use MEM_RELEASE.
	arenaBase := shadowArena.hostBase.Load()
	if arenaBase != 0 && entry.hostAddr >= arenaBase &&
		entry.hostAddr < arenaBase+shadowArenaSize {
		windows.VirtualFree(entry.hostAddr, uintptr(entry.size), windows.MEM_DECOMMIT)
	} else {
		windows.VirtualFree(entry.hostAddr, 0, windows.MEM_RELEASE)
	}

	return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, 1, 0, 0) // BOOL TRUE
}

// execShadowEntryPoint handles SyscallN calls where the proc address points
// into shadow memory (native code loaded by a COFF/BOF loader). It:
//  1. Pre-syncs ALL shadow regions from WASM → Host
//  2. Translates handle IDs in host memory to real native addresses (GOT fixup)
//  3. Translates pointer arguments (shadow addrs → host addrs, WASM heap ptrs → temp host buffers)
//  4. Executes the native code at the host entry point
//  5. Post-syncs ALL shadow regions from Host → WASM
func execShadowEntryPoint(mod api.Module, sm *shadowMap, ht *win32HandleTable, hostEntryPoint uintptr, nargs int32, args []uintptr, ret1Ptr, ret2Ptr, lastErrPtr uint32) uint32 {
	if entry := shadowEntryForPEEntrypoint(sm, hostEntryPoint, nargs, args); entry != nil {
		return execShadowPEEntrypoint(mod, entry, hostEntryPoint, args, ret1Ptr, ret2Ptr, lastErrPtr)
	}

	entries := sm.GetAll()

	// Pre-sync: copy ALL shadow regions from WASM → Host.
	// Temporarily make writable if the current protection doesn't allow writes.
	for _, e := range entries {
		var tmpOldP uint32
		needRestore := false
		if e.protect != uint32(windows.PAGE_READWRITE) && e.protect != uint32(windows.PAGE_EXECUTE_READWRITE) {
			windows.VirtualProtect(e.hostAddr, uintptr(e.size), windows.PAGE_READWRITE, &tmpOldP)
			needRestore = true
		}

		wasmData, ok := readBytes(mod, e.wasmAddr, e.size)
		if ok {
			hostSlice := unsafeSlice(e.hostAddr, e.size)
			copy(hostSlice, wasmData)
			flushInstructionCache(e.hostAddr, uintptr(e.size))
		}

		// Restore the actual protection.
		if needRestore {
			var tmpP uint32
			windows.VirtualProtect(e.hostAddr, uintptr(e.size), e.protect, &tmpP)
		}
	}

	// GOT fixup: scan all shadow regions for handle IDs and replace them
	// with real native procedure addresses. The COFF loader writes handle
	// IDs (from GetProcAddress, which returns guest handle IDs on WASM) into
	// the GOT. Native code does indirect calls through these entries, so they
	// must contain real x64 addresses.
	if ht != nil {
		procMap := ht.procAddrs()
		if len(procMap) > 0 {
			for _, e := range entries {
				// Only scan writable regions (GOT, .data, .bss — not .text).
				if e.protect == uint32(windows.PAGE_EXECUTE_READ) {
					continue
				}
				var tmpOldP uint32
				needRestore := false
				if e.protect != uint32(windows.PAGE_READWRITE) && e.protect != uint32(windows.PAGE_EXECUTE_READWRITE) {
					windows.VirtualProtect(e.hostAddr, uintptr(e.size), windows.PAGE_READWRITE, &tmpOldP)
					needRestore = true
				}

				// Scan 8-byte aligned slots for handle IDs.
				hostSlice := unsafeSlice(e.hostAddr, e.size)
				for off := uint32(0); off+8 <= e.size; off += 8 {
					val := binary.LittleEndian.Uint64(hostSlice[off : off+8])
					// Handle IDs are small positive int32 values in [win32BaseHandle, ...).
					// They fit in the lower 32 bits with upper 32 bits zero.
					if val >= win32BaseHandle && val < maxGuestHandleID {
						handleID := int32(val)
						if nativeAddr, ok := procMap[handleID]; ok {
							binary.LittleEndian.PutUint64(hostSlice[off:off+8], uint64(nativeAddr))
						}
					}
				}

				if needRestore {
					var tmpP uint32
					windows.VirtualProtect(e.hostAddr, uintptr(e.size), e.protect, &tmpP)
				}
			}
		}
	}

	// Translate pointer arguments.
	var tempBufs [][]byte // kept alive through the native call
	wasmMemSize := mod.Memory().Size()

	for i := int32(0); i < nargs; i++ {
		wasmVal := uint32(args[i])

		// Check if arg is in a shadow allocation → translate to host addr.
		if se := sm.LookupContaining(wasmVal); se != nil {
			offset := uintptr(wasmVal - se.wasmAddr)
			args[i] = se.hostAddr + offset
			continue
		}

		// Check if arg is a non-shadow WASM pointer (e.g., a packed arg
		// buffer allocated on the Go heap). Use the next arg as a size hint
		// (common calling convention: buffer_ptr, buffer_len).
		if wasmVal > 0 && wasmVal < wasmMemSize && i+1 < nargs {
			nextVal := uint32(args[i+1])
			if nextVal > 0 && nextVal < 0x1000000 { // reasonable size < 16MB
				data, ok := readBytes(mod, wasmVal, nextVal)
				if ok {
					tmp := make([]byte, nextVal)
					copy(tmp, data)
					args[i] = uintptr(unsafe.Pointer(&tmp[0]))
					tempBufs = append(tempBufs, tmp)
				}
			}
		}
	}

	// Execute native code at the entry point.
	r1, r2, err := syscall.SyscallN(hostEntryPoint, args...)

	// Keep temporary buffers alive through the syscall.
	runtime.KeepAlive(tempBufs)

	// Post-sync: copy ALL shadow regions from Host → WASM.
	for _, e := range entries {
		hostSlice := unsafeSlice(e.hostAddr, e.size)
		hostData := make([]byte, e.size)
		copy(hostData, hostSlice)
		writeBytes(mod, e.wasmAddr, hostData)
	}

	return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, r1, r2, uintptr(err))
}

func shadowEntryForPEEntrypoint(sm *shadowMap, hostEntryPoint uintptr, nargs int32, args []uintptr) *shadowEntry {
	if sm == nil || nargs != 3 || len(args) < 3 {
		return nil
	}
	for _, entry := range sm.GetAll() {
		if hostEntryPoint < entry.hostAddr || hostEntryPoint >= entry.hostAddr+uintptr(entry.size) {
			continue
		}
		if uint32(args[0]) == entry.wasmAddr {
			return &entry
		}
	}
	return nil
}

func execShadowPEEntrypoint(mod api.Module, entry *shadowEntry, hostEntryPoint uintptr, args []uintptr, ret1Ptr, ret2Ptr, lastErrPtr uint32) uint32 {
	var oldProtect uint32
	if err := windows.VirtualProtect(entry.hostAddr, uintptr(entry.size), windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, 0, 0, uintptr(win32Errno(err)))
	}

	wasmData, ok := readBytes(mod, entry.wasmAddr, entry.size)
	if !ok {
		return errnoEFAULT
	}
	hostSlice := unsafeSlice(entry.hostAddr, entry.size)
	copy(hostSlice, wasmData)
	flushInstructionCache(entry.hostAddr, uintptr(entry.size))

	r1, r2, err := syscall.SyscallN(hostEntryPoint, entry.hostAddr, args[1], args[2])
	return writeReturnValues(mod, ret1Ptr, ret2Ptr, lastErrPtr, r1, r2, uintptr(err))
}
