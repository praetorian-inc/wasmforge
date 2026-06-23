// WasmForge wasip1 shim for golang.org/x/sys/windows.
//
// Most types, constants, and functions are now provided by the full
// sysshim files (types.go, security.go, zsyscall.go, etc.) which
// have been enabled for wasip1. This file only contains:
//
//  1. Core types (Handle, HWND) and constants (InvalidHandle) that
//     are defined in syscallwin.go (windows-only)
//  2. Standard handle vars (Stdout, Stderr, Stdin) from syscallwin.go
//  3. CurrentProcess() from syscallwin.go
//  4. DLL/Proc/LazyDLL/LazyProc implementations that route through
//     wasmforge's wasm-imported syscall shims
//  5. NewCallback/NewCallbackCDecl via wasm imports
//  6. Extension output drain (wasmforge-specific)
//  7. Race stubs (wasip1 never uses -race)

//go:build wasip1

package windows

import (
	"encoding/binary"
	"reflect"
	"sync"
	"syscall"
	"unsafe"
)

// --- Core Types (from syscallwin.go, which stays windows-only) ---

type (
	Handle uintptr
	HWND   uintptr
)

const (
	InvalidHandle = ^Handle(0)
	InvalidHWND   = ^HWND(0)
)

// --- Standard Handle Vars (from syscallwin.go) ---

var Stdout Handle = Handle(STD_OUTPUT_HANDLE)
var Stderr Handle = Handle(STD_ERROR_HANDLE)
var Stdin Handle = Handle(STD_INPUT_HANDLE)

// --- CurrentProcess (from syscallwin.go) ---

// CurrentProcess returns a handle for the current process (pseudo-handle).
func CurrentProcess() Handle {
	return ^Handle(0) // -1 pseudo-handle
}

// --- Timespec (from syscallwin.go, which stays windows-only) ---

// Timespec is an invented structure on Windows, but here for
// consistency with the corresponding package for other operating systems.
type Timespec struct {
	Sec  int64
	Nsec int64
}

func TimespecToNsec(ts Timespec) int64 { return int64(ts.Sec)*1e9 + int64(ts.Nsec) }

func NsecToTimespec(nsec int64) (ts Timespec) {
	ts.Sec = nsec / 1e9
	ts.Nsec = nsec % 1e9
	return
}

// --- Race stubs (wasip1 never uses -race) ---

const raceenabled = false

func raceAcquire(addr unsafe.Pointer)             {}
func raceReleaseMerge(addr unsafe.Pointer)        {}
func raceReadRange(addr unsafe.Pointer, len int)  {}
func raceWriteRange(addr unsafe.Pointer, len int) {}

// --- DLL Loading ---

// DLLError describes reasons for DLL load failures.
type DLLError struct {
	Err     error
	ObjName string
	Msg     string
}

func (e *DLLError) Error() string { return e.Msg }
func (e *DLLError) Unwrap() error { return e.Err }

// DLL implements access to a single DLL.
type DLL struct {
	Name   string
	Handle Handle
}

// LoadDLL loads a DLL file.
func LoadDLL(name string) (dll *DLL, err error) {
	d, e := syscall.LoadDLL(name)
	if e != nil {
		return nil, &DLLError{
			Err:     e,
			ObjName: name,
			Msg:     "Failed to load " + name + ": " + e.Error(),
		}
	}
	return &DLL{Name: d.Name, Handle: Handle(d.Handle)}, nil
}

// MustLoadDLL is like LoadDLL but panics on error.
func MustLoadDLL(name string) *DLL {
	d, err := LoadDLL(name)
	if err != nil {
		panic(err)
	}
	return d
}

// FindProc searches the DLL for a named procedure.
func (d *DLL) FindProc(name string) (proc *Proc, err error) {
	sd := &syscall.DLL{Name: d.Name, Handle: syscall.Handle(d.Handle)}
	p, e := sd.FindProc(name)
	if e != nil {
		return nil, &DLLError{
			Err:     e,
			ObjName: name,
			Msg:     "Failed to find " + name + " in " + d.Name + ": " + e.Error(),
		}
	}
	return &Proc{Dll: d, Name: p.Name, addr: p.Addr()}, nil
}

// MustFindProc is like FindProc but panics on error.
func (d *DLL) MustFindProc(name string) *Proc {
	p, err := d.FindProc(name)
	if err != nil {
		panic(err)
	}
	return p
}

// Release unloads the DLL.
func (d *DLL) Release() error {
	return syscall.FreeLibrary(syscall.Handle(d.Handle))
}

// --- Proc ---

// Proc implements access to a procedure inside a DLL.
type Proc struct {
	Dll  *DLL
	Name string
	addr uintptr
}

// Addr returns the address of the procedure.
func (p *Proc) Addr() uintptr {
	return p.addr
}

// Call executes the procedure with the given arguments.
func (p *Proc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
	r1, r2, errno := syscall.SyscallN(p.addr, a...)
	if errno != 0 {
		lastErr = errno
	}
	return
}

// --- LazyDLL ---

// LazyDLL implements a lazily loaded DLL.
type LazyDLL struct {
	Name   string
	System bool
	dll    *DLL
}

// NewLazyDLL creates a new lazy DLL loader.
func NewLazyDLL(name string) *LazyDLL {
	return &LazyDLL{Name: name}
}

// NewLazySystemDLL is like NewLazyDLL but restricts search to system directory.
func NewLazySystemDLL(name string) *LazyDLL {
	return &LazyDLL{Name: name, System: true}
}

// Load loads the DLL if not already loaded.
func (d *LazyDLL) Load() error {
	if d.dll != nil {
		return nil
	}
	dll, err := LoadDLL(d.Name)
	if err != nil {
		return err
	}
	d.dll = dll
	return nil
}

// Handle returns the module handle.
func (d *LazyDLL) Handle() uintptr {
	if err := d.Load(); err != nil {
		return 0
	}
	return uintptr(d.dll.Handle)
}

// NewProc creates a lazy procedure reference.
func (d *LazyDLL) NewProc(name string) *LazyProc {
	return &LazyProc{l: d, Name: name}
}

// --- LazyProc ---

// LazyProc implements a lazily resolved procedure.
type LazyProc struct {
	Name string
	l    *LazyDLL
	proc *Proc
}

// Find resolves the procedure address.
func (p *LazyProc) Find() error {
	if p.proc != nil {
		return nil
	}
	if err := p.l.Load(); err != nil {
		return err
	}
	proc, err := p.l.dll.FindProc(p.Name)
	if err != nil {
		return err
	}
	p.proc = proc
	return nil
}

// Addr returns the address of the procedure.
func (p *LazyProc) Addr() uintptr {
	if err := p.Find(); err != nil {
		return 0
	}
	return p.proc.Addr()
}

// Call executes the procedure.
func (p *LazyProc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
	if err := p.Find(); err != nil {
		return 0, 0, err
	}
	return p.proc.Call(a...)
}

// --- Extension Output Drain Support ---

//go:wasmimport env ext_readout
//go:noescape
func win32_ext_read_output(bufPtr *byte, bufLen uint32, actualLenPtr *byte) uint32

//go:wasmimport env ext_resetout
func win32_ext_reset_output() uint32

// extOutputMu protects the ext callback variables.
var extOutputMu sync.Mutex

// extOutputCallback stores the Output-type callback (preferred).
var extOutputCallback func(int, uintptr, int) uintptr

// extPrintfCallback stores the Printf-type callback (fallback when Output is unavailable).
// Used to route host buffer data through the Printf path with a "%s" format.
type extPrintfFunc = func(int, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) uintptr

var extPrintfCallback extPrintfFunc

// extExtensionCallback stores the Sliver extension callback.
var extExtensionCallback func(uintptr, uintptr) uintptr

func init() {
	syscall.AfterSyscallNHook = drainExtensionOutput
}

// drainExtensionOutput reads accumulated extension API output from the host
// buffer and routes it through the registered Output callback to the guest's
// channel. Called after every SyscallN; no-op when no callback is registered
// or the host buffer is empty.
func drainExtensionOutput(trap uintptr) {
	extOutputMu.Lock()
	outputCB := extOutputCallback
	printfCB := extPrintfCallback
	extCB := extExtensionCallback
	extOutputMu.Unlock()

	syscallExtCB := syscall.ExtensionCallbackFn

	if outputCB == nil && printfCB == nil && extCB == nil && syscallExtCB == nil {
		return
	}

	// Read output from host buffer.
	var actualLenBuf [4]byte
	var probe [1]byte
	errno := win32_ext_read_output(&probe[0], 0, &actualLenBuf[0])
	if errno != 0 {
		return
	}
	actualLen := binary.LittleEndian.Uint32(actualLenBuf[:])
	if actualLen == 0 {
		return
	}

	// Allocate exact-size buffer and read.
	buf := make([]byte, actualLen)
	errno = win32_ext_read_output(&buf[0], actualLen, &actualLenBuf[0])
	if errno != 0 {
		return
	}

	if outputCB != nil {
		outputCB(0, uintptr(unsafe.Pointer(&buf[0])), int(actualLen))
	} else if syscallExtCB != nil {
		syscallExtCB(uintptr(unsafe.Pointer(&buf[0])), uintptr(actualLen))
	} else if extCB != nil {
		extCB(uintptr(unsafe.Pointer(&buf[0])), uintptr(actualLen))
	} else if printfCB != nil {
		fmtStr := [3]byte{'%', 's', 0}
		dataBuf := make([]byte, actualLen+1)
		copy(dataBuf, buf)
		printfCB(0, uintptr(unsafe.Pointer(&fmtStr[0])), uintptr(unsafe.Pointer(&dataBuf[0])), 0, 0, 0, 0, 0, 0, 0, 0, 0)
	}

	// Clear the host buffer.
	win32_ext_reset_output()
}

// --- Native Callback Support ---

//go:wasmimport env ext_callback
//go:noescape
func win32_new_callback(namePtr *byte, nameLen int32, addrPtr *byte) int32

// NewCallback converts a Go function to a native function pointer conforming
// to the stdcall calling convention.
//
// On wasip1, WASM cannot create native function pointers directly. Instead,
// this uses the function signature as a hint to the host, which maps it to a
// pre-created Extension API callback. This supports Beacon API callbacks
// (Output, Printf, DataParse, etc.) used by COFF/BOF loaders.
func NewCallback(fn interface{}) uintptr {
	fnType := reflect.TypeOf(fn)
	var hint string
	uptrType := reflect.TypeOf(uintptr(0))
	intType := reflect.TypeOf(int(0))

	if fnType != nil && fnType.Kind() == reflect.Func && fnType.NumOut() == 1 && fnType.Out(0) == uptrType {
		numIn := fnType.NumIn()
		if numIn == 3 && fnType.In(0) == intType && fnType.In(1) == uptrType && fnType.In(2) == intType {
			hint = "Output"
			v := reflect.ValueOf(fn)
			extOutputMu.Lock()
			extOutputCallback = func(a int, b uintptr, c int) uintptr {
				r := v.Call([]reflect.Value{reflect.ValueOf(a), reflect.ValueOf(b), reflect.ValueOf(c)})
				return r[0].Interface().(uintptr)
			}
			extOutputMu.Unlock()
		} else if isPrintfCallbackType(fnType, intType, uptrType) {
			hint = "Printf"
			v := reflect.ValueOf(fn)
			extOutputMu.Lock()
			extPrintfCallback = func(a0 int, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 uintptr) uintptr {
				r := v.Call([]reflect.Value{
					reflect.ValueOf(a0),
					reflect.ValueOf(a1), reflect.ValueOf(a2), reflect.ValueOf(a3), reflect.ValueOf(a4),
					reflect.ValueOf(a5), reflect.ValueOf(a6), reflect.ValueOf(a7), reflect.ValueOf(a8),
					reflect.ValueOf(a9), reflect.ValueOf(a10), reflect.ValueOf(a11),
				})
				return r[0].Interface().(uintptr)
			}
			extOutputMu.Unlock()
		} else if numIn == 2 && fnType.In(0) == uptrType && fnType.In(1) == uptrType {
			hint = "extensionCallback"
			v := reflect.ValueOf(fn)
			extOutputMu.Lock()
			extExtensionCallback = func(data uintptr, length uintptr) uintptr {
				r := v.Call([]reflect.Value{reflect.ValueOf(data), reflect.ValueOf(length)})
				return r[0].Interface().(uintptr)
			}
			extOutputMu.Unlock()
		}
	}

	nameBytes := []byte(hint)
	var addrBuf [8]byte
	var namePtr *byte
	if len(nameBytes) > 0 {
		namePtr = &nameBytes[0]
	}
	errno := win32_new_callback(namePtr, int32(len(nameBytes)), &addrBuf[0])
	if errno != 0 {
		return 0
	}
	return uintptr(binary.LittleEndian.Uint64(addrBuf[:]))
}

func isPrintfCallbackType(fnType reflect.Type, intType, uptrType reflect.Type) bool {
	if fnType.NumIn() != 12 || fnType.In(0) != intType || fnType.In(1) != uptrType {
		return false
	}
	for i := 2; i < fnType.NumIn(); i++ {
		if fnType.In(i) != uptrType {
			return false
		}
	}
	return true
}

// NewCallbackCDecl converts a Go function to a function pointer conforming
// to the cdecl calling convention. On wasip1, this delegates to NewCallback.
func NewCallbackCDecl(fn interface{}) uintptr {
	return NewCallback(fn)
}
