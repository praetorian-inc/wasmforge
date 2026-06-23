// WasmForge Win32 syscall shim for wasip1.
// Provides Windows syscall primitives (DLL, Proc, SyscallN) that route
// through wasmforge host functions, enabling golang.org/x/sys/windows
// to work transparently in WASM.

//go:build wasip1

package syscall

import (
	"unsafe"
)

const _ERRNO_YIELD = 255

// goYield creates a scheduling point without importing runtime.
// The unbuffered channel receive blocks this goroutine, allowing
// the Go scheduler to run other goroutines. The spawned goroutine
// immediately sends, so the current goroutine resumes quickly.
// Cost: one goroutine per yield — negligible for blocking Win32 calls.
func goYield() {
	c := make(chan struct{})
	go func() { c <- struct{}{} }()
	<-c
}

// Win32 host function imports.

//go:wasmimport env mod_load
//go:noescape
func win32_load_library(namePtr *byte, nameLen int32, handlePtr *int32) int32

//go:wasmimport env mod_resolve
//go:noescape
func win32_get_proc_address(libHandle int32, namePtr *byte, nameLen int32, procPtr *int32) int32

//go:wasmimport env mod_free
//go:noescape
func win32_free_library(handle int32) int32

//go:wasmimport env mod_invoke
//go:noescape
func win32_syscalln(proc int32, nargs int32, argsPtr *byte, ret1Ptr *byte, ret2Ptr *byte, lastErrPtr *byte) int32

//go:wasmimport env mem_addr
//go:noescape
func win32_hmem_addr(handle int32, addrPtr uint32) uint32

// Shadow memory host function imports.

//go:wasmimport env shm_alloc
//go:noescape
func shadow_virtual_alloc(wasmAddr uint32, size uint32, allocType uint32, protect uint32) uint32

//go:wasmimport env shm_protect
//go:noescape
func shadow_virtual_protect(wasmAddr uint32, size uint32, newProtect uint32, oldProtectPtr uint32) uint32

//go:wasmimport env shm_free
//go:noescape
func shadow_virtual_free(wasmAddr uint32, size uint32, freeType uint32) uint32

// ShadowVirtualAlloc registers a shadow allocation. wasmAddr is the WASM-side
// buffer address, size/allocType/protect are the VirtualAlloc parameters.
// Returns 0 on success, or a Windows error code.
func ShadowVirtualAlloc(wasmAddr, size, allocType, protect uint32) uint32 {
	return shadow_virtual_alloc(wasmAddr, size, allocType, protect)
}

// ShadowVirtualProtect changes protection on a shadow allocation and syncs
// WASM↔Host memory. Returns 0 on success, or a Windows error code.
func ShadowVirtualProtect(wasmAddr, size, newProtect, oldProtectPtr uint32) uint32 {
	return shadow_virtual_protect(wasmAddr, size, newProtect, oldProtectPtr)
}

// ShadowVirtualFree releases a shadow allocation. Returns 0 on success.
func ShadowVirtualFree(wasmAddr, size, freeType uint32) uint32 {
	return shadow_virtual_free(wasmAddr, size, freeType)
}

// HostMemoryAddress returns the real host address for a host memory handle or
// WASM shadow allocation address. Returns 0 on success.
func HostMemoryAddress(handleOrAddr uint32, addrPtr uint32) uint32 {
	return win32_hmem_addr(int32(handleOrAddr), addrPtr)
}

// putUint64LE writes v to b in little-endian order.
func putUint64LE(b []byte, v uint64) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

// getUint64LE reads a little-endian uint64 from b.
func getUint64LE(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// DLL implements a Windows DLL (Dynamic Link Library).
// This mirrors the real syscall.DLL type on Windows.
type DLL struct {
	Name   string
	Handle Handle // guest handle from win32_load_library
}

// Proc implements a procedure in a DLL.
// This mirrors the real syscall.Proc type on Windows.
type Proc struct {
	Dll  *DLL
	Name string
	addr uintptr
}

// Handle is a Windows HANDLE type.
type Handle uintptr

// InvalidHandle is the Windows INVALID_HANDLE_VALUE.
const InvalidHandle = ^Handle(0)

// Errno is already defined in the syscall package for wasip1,
// so we DON'T redefine it here. But we need Windows-specific
// error constants.

// Windows error codes used by x/sys/windows.
const (
	ERROR_SUCCESS             = Errno(0)
	ERROR_FILE_NOT_FOUND      = Errno(2)
	ERROR_PATH_NOT_FOUND      = Errno(3)
	ERROR_ACCESS_DENIED       = Errno(5)
	ERROR_INVALID_HANDLE      = Errno(6)
	ERROR_NOT_ENOUGH_MEMORY   = Errno(8)
	ERROR_NO_MORE_FILES       = Errno(18)
	ERROR_SHARING_VIOLATION   = Errno(32)
	ERROR_ALREADY_EXISTS      = Errno(183)
	ERROR_ENVVAR_NOT_FOUND    = Errno(203)
	ERROR_MORE_DATA           = Errno(234)
	ERROR_OPERATION_ABORTED   = Errno(995)
	ERROR_IO_PENDING          = Errno(997)
	ERROR_PROC_NOT_FOUND      = Errno(127)
	ERROR_MOD_NOT_FOUND       = Errno(126)
	ERROR_INSUFFICIENT_BUFFER = Errno(122)

	// _WIN32_ENOSYS is returned by host stubs that are not implemented.
	_WIN32_ENOSYS = 52

	// APPLICATION_ERROR is the base for invented errno values (mirrors zerrors_windows.go).
	APPLICATION_ERROR = Errno(1 << 29)

	// EWINDOWS is an invented errno for "not supported by windows".
	EWINDOWS = APPLICATION_ERROR + 130
)

// LoadDLL loads a Windows DLL.
func LoadDLL(name string) (*DLL, error) {
	if len(name) == 0 {
		return nil, EINVAL
	}
	b := []byte(name)
	var h int32
	errno := win32_load_library(&b[0], int32(len(b)), &h)
	if errno != 0 {
		if errno == _WIN32_ENOSYS {
			return nil, ENOSYS
		}
		return nil, Errno(errno)
	}
	return &DLL{Name: name, Handle: Handle(h)}, nil
}

// MustLoadDLL is like LoadDLL but panics on error.
func MustLoadDLL(name string) *DLL {
	d, err := LoadDLL(name)
	if err != nil {
		panic("syscall: could not load DLL " + name + ": " + err.Error())
	}
	return d
}

// FindProc finds a procedure in the DLL.
func (d *DLL) FindProc(name string) (*Proc, error) {
	if len(name) == 0 {
		return nil, EINVAL
	}
	b := []byte(name)
	var p int32
	errno := win32_get_proc_address(int32(d.Handle), &b[0], int32(len(b)), &p)
	if errno != 0 {
		if errno == _WIN32_ENOSYS {
			return nil, ENOSYS
		}
		return nil, Errno(errno)
	}
	return &Proc{Dll: d, Name: name, addr: uintptr(p)}, nil
}

// MustFindProc is like FindProc but panics on error.
func (d *DLL) MustFindProc(name string) *Proc {
	p, err := d.FindProc(name)
	if err != nil {
		panic("syscall: could not find proc " + name + " in " + d.Name + ": " + err.Error())
	}
	return p
}

// Release releases the DLL.
func (d *DLL) Release() error {
	errno := win32_free_library(int32(d.Handle))
	if errno != 0 {
		return Errno(errno)
	}
	return nil
}

// Addr returns the address of the procedure.
func (p *Proc) Addr() uintptr {
	return p.addr
}

// Call calls a procedure with the given arguments.
// Always returns Errno (even Errno(0)) as the error, matching real Windows
// syscall.Proc.Call behavior. Code like go-clr checks `err != syscall.Errno(0)`
// which requires a non-nil Errno interface value, not nil.
// Errno(0).Error() is patched to return "The operation completed successfully."
// (matching Windows FormatMessage for error 0) so goffloader-style string
// comparisons also work correctly.
func (p *Proc) Call(a ...uintptr) (uintptr, uintptr, error) {
	r1, r2, lastErr := SyscallN(p.Addr(), a...)
	return r1, r2, lastErr
}

// AfterSyscallNHook is called after each successful SyscallN with the proc handle.
// The sysshim uses this to drain extension API output after BOF execution.
var AfterSyscallNHook func(trap uintptr)

// ExtensionCallbackFn stores the most recently registered extension callback
// (func(data uintptr, dataLen uintptr) uintptr) so the sysshim drain hook
// can invoke it with data read from the host buffer. Set by syscall.NewCallback
// when the function signature matches the extension callback pattern.
var ExtensionCallbackFn func(uintptr, uintptr) uintptr

// SyscallN calls a Windows procedure with N arguments.
// This is the primary interception point — golang.org/x/sys/windows
// routes all Windows API calls through this function.
func SyscallN(trap uintptr, args ...uintptr) (r1, r2 uintptr, err Errno) {
	if len(args) > 15 {
		return 0, 0, EINVAL
	}

	// Pack args as int64 array (8 bytes each, little-endian).
	var argBuf [15 * 8]byte
	for i, a := range args {
		putUint64LE(argBuf[i*8:], uint64(a))
	}

	var ret1Buf, ret2Buf, errBuf [8]byte
	var argsPtr *byte
	if len(args) > 0 {
		argsPtr = &argBuf[0]
	}

	for {
		errno := win32_syscalln(int32(trap), int32(len(args)), argsPtr, &ret1Buf[0], &ret2Buf[0], &errBuf[0])
		if errno == _ERRNO_YIELD {
			goYield()
			continue
		}
		if errno != 0 {
			return 0, 0, Errno(errno)
		}
		break
	}

	r1 = uintptr(getUint64LE(ret1Buf[:]))
	r2 = uintptr(getUint64LE(ret2Buf[:]))
	lastErr := Errno(getUint64LE(errBuf[:]))

	// Call post-SyscallN hook (e.g., to drain extension output after BOF execution).
	if AfterSyscallNHook != nil {
		AfterSyscallNHook(trap)
	}

	return r1, r2, lastErr
}

// Syscall calls a Windows procedure with 3 arguments.
func Syscall(trap, nargs, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno) {
	return SyscallN(trap, a1, a2, a3)
}

// Syscall6 calls a Windows procedure with 6 arguments.
func Syscall6(trap, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno) {
	return SyscallN(trap, a1, a2, a3, a4, a5, a6)
}

// Syscall9 calls a Windows procedure with 9 arguments.
func Syscall9(trap, nargs, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err Errno) {
	return SyscallN(trap, a1, a2, a3, a4, a5, a6, a7, a8, a9)
}

// Syscall12 calls a Windows procedure with 12 arguments.
func Syscall12(trap, nargs, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12 uintptr) (r1, r2 uintptr, err Errno) {
	return SyscallN(trap, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12)
}

// Syscall15 calls a Windows procedure with 15 arguments.
func Syscall15(trap, nargs, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15 uintptr) (r1, r2 uintptr, err Errno) {
	return SyscallN(trap, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15)
}

// win32_new_callback host function import for NewCallback support.

//go:wasmimport env ext_callback
//go:noescape
func win32_new_callback(namePtr *byte, nameLen int32, addrPtr *byte) int32

// NewCallback creates a native function pointer from a Go function.
// On wasip1, this sends a hint to the host which maps it to a pre-created
// Extension API callback. The hint tells the host which callback type to
// return. This package avoids reflect to prevent a syscall import cycle, so
// matching is limited to known callback signatures.
func NewCallback(fn interface{}) uintptr {
	var hint string
	switch cb := fn.(type) {
	case func(uintptr, uintptr) uintptr:
		hint = "extensionCallback"
		ExtensionCallbackFn = cb
	case func(int, uintptr, int) uintptr:
		hint = "Output"
	case func(uintptr, uintptr, uintptr) uintptr:
		hint = "Output"
	case func(uintptr) uintptr:
		hint = "DataLength"
	case func(uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) uintptr:
		hint = "Printf"
	}

	var addrBuf [8]byte
	if hint != "" {
		hintBytes := []byte(hint)
		errno := win32_new_callback(&hintBytes[0], int32(len(hintBytes)), &addrBuf[0])
		if errno != 0 {
			return 0
		}
	} else {
		errno := win32_new_callback(nil, 0, &addrBuf[0])
		if errno != 0 {
			return 0
		}
	}
	return uintptr(getUint64LE(addrBuf[:]))
}

// NewCallbackCDecl creates a native function pointer with cdecl convention.
func NewCallbackCDecl(fn interface{}) uintptr {
	return NewCallback(fn)
}

// GetLastError returns 0 (stub). Real implementation is in host.
func GetLastError() uint32 {
	return 0
}

// EscapeArg escapes a Windows command-line argument, adding double quotes
// around it if it contains spaces or tabs. Backslashes and quotes are escaped.
func EscapeArg(s string) string {
	if len(s) == 0 {
		return `""`
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\\', ' ', '\t':
			b := make([]byte, 0, len(s)+2)
			b = appendEscapeArg(b, s)
			return string(b)
		}
	}
	return s
}

func appendEscapeArg(b []byte, s string) []byte {
	if len(s) == 0 {
		return append(b, `""`...)
	}
	needsBackslash := false
	hasSpace := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\\':
			needsBackslash = true
		case ' ', '\t':
			hasSpace = true
		}
	}
	if !needsBackslash && !hasSpace {
		return append(b, s...)
	}
	if !needsBackslash {
		b = append(b, '"')
		b = append(b, s...)
		return append(b, '"')
	}
	if hasSpace {
		b = append(b, '"')
	}
	slashes := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		default:
			slashes = 0
			b = append(b, s[i])
		case '\\':
			slashes++
			b = append(b, s[i])
		case '"':
			for ; slashes > 0; slashes-- {
				b = append(b, '\\')
			}
			b = append(b, '\\', s[i])
		}
	}
	if hasSpace {
		for ; slashes > 0; slashes-- {
			b = append(b, '\\')
		}
		b = append(b, '"')
	}
	return b
}

// LoadLibrary loads a DLL by name (string). This matches the real Windows
// syscall.LoadLibrary signature: func(libname string) (Handle, error).
func LoadLibrary(libname string) (Handle, error) {
	dll, err := LoadDLL(libname)
	if err != nil {
		return 0, err
	}
	return dll.Handle, nil
}

// LoadLibraryW loads a DLL by UTF-16 name pointer. Some code uses this variant.
func LoadLibraryW(name *uint16) (Handle, error) {
	s := UTF16PtrToString(name)
	return LoadLibrary(s)
}

// GetProcAddress finds a procedure in a DLL by name (string). This matches
// the real Windows syscall.GetProcAddress signature.
func GetProcAddress(module Handle, procname string) (uintptr, error) {
	d := &DLL{Handle: module}
	proc, err := d.FindProc(procname)
	if err != nil {
		return 0, err
	}
	return proc.Addr(), nil
}

// FreeLibrary releases a loaded DLL.
func FreeLibrary(module Handle) error {
	d := &DLL{Handle: module}
	return d.Release()
}

// UTF16PtrToString converts a UTF-16 pointer to a Go string.
func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	n := 0
	ptr := p
	for *ptr != 0 {
		n++
		ptr = (*uint16)(unsafe.Add(unsafe.Pointer(ptr), 2))
	}
	if n == 0 {
		return ""
	}
	s := unsafe.Slice(p, n)
	buf := make([]byte, 0, n*3)
	for _, c := range s {
		if c < 0x80 {
			buf = append(buf, byte(c))
		} else if c < 0x800 {
			buf = append(buf, byte(0xC0|(c>>6)), byte(0x80|(c&0x3F)))
		} else {
			buf = append(buf, byte(0xE0|(c>>12)), byte(0x80|((c>>6)&0x3F)), byte(0x80|(c&0x3F)))
		}
	}
	return string(buf)
}

// UTF16ToString converts a UTF-16 slice to a Go string.
func UTF16ToString(s []uint16) string {
	for i, v := range s {
		if v == 0 {
			s = s[:i]
			break
		}
	}
	buf := make([]byte, 0, len(s)*3)
	for _, c := range s {
		if c < 0x80 {
			buf = append(buf, byte(c))
		} else if c < 0x800 {
			buf = append(buf, byte(0xC0|(c>>6)), byte(0x80|(c&0x3F)))
		} else {
			buf = append(buf, byte(0xE0|(c>>12)), byte(0x80|((c>>6)&0x3F)), byte(0x80|(c&0x3F)))
		}
	}
	return string(buf)
}

// UTF16FromString returns the UTF-16 encoding of the UTF-8 string s,
// with a terminating NUL added. If s contains a NUL byte at any
// location, it returns (nil, EINVAL).
func UTF16FromString(s string) ([]uint16, error) {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return nil, EINVAL
		}
	}
	return StringToUTF16(s), nil
}

// UTF16PtrFromString returns pointer to the UTF-16 encoding of
// the UTF-8 string s, with a terminating NUL added. If s
// contains a NUL byte at any location, it returns (nil, EINVAL).
func UTF16PtrFromString(s string) (*uint16, error) {
	a, err := UTF16FromString(s)
	if err != nil {
		return nil, err
	}
	return &a[0], nil
}

// StringToUTF16 converts a Go string to UTF-16.
func StringToUTF16(s string) []uint16 {
	a := make([]uint16, 0, len(s)+1)
	for _, r := range s {
		if r < 0x10000 {
			a = append(a, uint16(r))
		} else {
			r -= 0x10000
			a = append(a, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		}
	}
	a = append(a, 0) // null terminator
	return a
}

// StringToUTF16Ptr converts a Go string to a *uint16 pointer.
func StringToUTF16Ptr(s string) *uint16 {
	a := StringToUTF16(s)
	return &a[0]
}

// LazyDLL implements a lazily-loaded DLL. This is what x/sys/windows uses.
type LazyDLL struct {
	Name string
	mu   [0]byte // prevent copying
	dll  *DLL
}

// NewLazyDLL creates a new lazy DLL loader.
func NewLazyDLL(name string) *LazyDLL {
	return &LazyDLL{Name: name}
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

// Handle returns the DLL handle as a uintptr.
func (d *LazyDLL) Handle() uintptr {
	if err := d.Load(); err != nil {
		return 0
	}
	return uintptr(d.dll.Handle)
}

// NewProc creates a lazy procedure in the DLL.
func (d *LazyDLL) NewProc(name string) *LazyProc {
	return &LazyProc{l: d, Name: name}
}

// LazyProc implements a lazily-resolved procedure address.
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

// Addr returns the procedure address.
func (p *LazyProc) Addr() uintptr {
	if err := p.Find(); err != nil {
		return 0
	}
	return p.proc.Addr()
}

// Call calls the procedure.
func (p *LazyProc) Call(a ...uintptr) (uintptr, uintptr, error) {
	if err := p.Find(); err != nil {
		return 0, 0, err
	}
	return p.proc.Call(a...)
}

// --- Registry constants and functions ---
// Used by golang.org/x/sys/windows/registry sub-package.

const (
	HKEY_CLASSES_ROOT     = Handle(0x80000000)
	HKEY_CURRENT_USER     = Handle(0x80000001)
	HKEY_LOCAL_MACHINE    = Handle(0x80000002)
	HKEY_USERS            = Handle(0x80000003)
	HKEY_PERFORMANCE_DATA = Handle(0x80000004)
	HKEY_CURRENT_CONFIG   = Handle(0x80000005)

	KEY_QUERY_VALUE        = 0x0001
	KEY_SET_VALUE          = 0x0002
	KEY_CREATE_SUB_KEY     = 0x0004
	KEY_ENUMERATE_SUB_KEYS = 0x0008
	KEY_NOTIFY             = 0x0010
	KEY_CREATE_LINK        = 0x0020
	KEY_WRITE              = 0x20006
	KEY_READ               = 0x20019
	KEY_WOW64_64KEY        = 0x0100
	KEY_WOW64_32KEY        = 0x0200
	KEY_ALL_ACCESS         = 0xF003F

	MAX_ADAPTER_ADDRESS_LENGTH = 8

	ERROR_NO_MORE_ITEMS = Errno(259)
)

// Filetime mirrors Windows FILETIME.
type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

// Nanoseconds returns Filetime ft in nanoseconds since Epoch (00:00:00 UTC, January 1, 1970).
func (ft *Filetime) Nanoseconds() int64 {
	// 100-nanosecond intervals since January 1, 1601
	nsec := int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime)
	// change starting time to the Epoch (00:00:00 UTC, January 1, 1970)
	nsec -= 116444736000000000
	// convert into nanoseconds
	nsec *= 100
	return nsec
}

// SecurityAttributes mirrors Windows SECURITY_ATTRIBUTES.
type SecurityAttributes struct {
	Length             uint32
	SecurityDescriptor uintptr
	InheritHandle      uint32
}

// RawSockaddrAny mirrors Windows RawSockaddrAny from the syscall package.
type RawSockaddrAny struct {
	Addr RawSockaddr
	Pad  [100]int8
}

// RawSockaddr mirrors Windows RawSockaddr.
type RawSockaddr struct {
	Family uint16
	Data   [14]int8
}

// Registry API wrappers via lazy DLL loading.

var (
	modadvapi32     = NewLazyDLL("advapi32.dll")
	modkernel32_reg = NewLazyDLL("kernel32.dll")

	procRegCloseKey      = modadvapi32.NewProc("RegCloseKey")
	procRegOpenKeyExW    = modadvapi32.NewProc("RegOpenKeyExW")
	procRegQueryInfoKeyW = modadvapi32.NewProc("RegQueryInfoKeyW")
	procRegEnumKeyExW    = modadvapi32.NewProc("RegEnumKeyExW")
	procRegQueryValueExW = modadvapi32.NewProc("RegQueryValueExW")
	procCloseHandle      = modkernel32_reg.NewProc("CloseHandle")
)

// RegCloseKey closes a registry key handle.
func RegCloseKey(key Handle) error {
	r1, _, _ := SyscallN(procRegCloseKey.Addr(), uintptr(key))
	if r1 != 0 {
		return Errno(r1)
	}
	return nil
}

// RegOpenKeyEx opens a registry key.
func RegOpenKeyEx(key Handle, subkey *uint16, options uint32, desiredAccess uint32, result *Handle) error {
	r1, _, _ := SyscallN(procRegOpenKeyExW.Addr(), uintptr(key), uintptr(unsafe.Pointer(subkey)), uintptr(options), uintptr(desiredAccess), uintptr(unsafe.Pointer(result)))
	if r1 != 0 {
		return Errno(r1)
	}
	return nil
}

// RegQueryInfoKey retrieves information about a registry key.
func RegQueryInfoKey(key Handle, class *uint16, classLen *uint32, reserved *uint32, subkeys *uint32, maxSubkeyLen *uint32, maxClassLen *uint32, values *uint32, maxValueNameLen *uint32, maxValueLen *uint32, saLen *uint32, lastWriteTime *Filetime) error {
	r1, _, _ := SyscallN(procRegQueryInfoKeyW.Addr(), uintptr(key), uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(classLen)), uintptr(unsafe.Pointer(reserved)), uintptr(unsafe.Pointer(subkeys)), uintptr(unsafe.Pointer(maxSubkeyLen)), uintptr(unsafe.Pointer(maxClassLen)), uintptr(unsafe.Pointer(values)), uintptr(unsafe.Pointer(maxValueNameLen)), uintptr(unsafe.Pointer(maxValueLen)), uintptr(unsafe.Pointer(saLen)), uintptr(unsafe.Pointer(lastWriteTime)))
	if r1 != 0 {
		return Errno(r1)
	}
	return nil
}

// RegEnumKeyEx enumerates the subkeys of a registry key.
func RegEnumKeyEx(key Handle, index uint32, name *uint16, nameLen *uint32, reserved *uint32, class *uint16, classLen *uint32, lastWriteTime *Filetime) error {
	r1, _, _ := SyscallN(procRegEnumKeyExW.Addr(), uintptr(key), uintptr(index), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(nameLen)), uintptr(unsafe.Pointer(reserved)), uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(classLen)), uintptr(unsafe.Pointer(lastWriteTime)))
	if r1 != 0 {
		return Errno(r1)
	}
	return nil
}

// RegQueryValueEx retrieves the type and data for a specified value name.
func RegQueryValueEx(key Handle, name *uint16, reserved *uint32, valtype *uint32, buf *byte, buflen *uint32) error {
	r1, _, _ := SyscallN(procRegQueryValueExW.Addr(), uintptr(key), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(reserved)), uintptr(unsafe.Pointer(valtype)), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(buflen)))
	if r1 != 0 {
		return Errno(r1)
	}
	return nil
}

// CloseHandle closes a Windows handle.
func CloseHandle(handle Handle) error {
	r1, _, e1 := SyscallN(procCloseHandle.Addr(), uintptr(handle))
	if r1 == 0 {
		return Errno(e1)
	}
	return nil
}

// --- Windows I/O types and constants ---

// CloseW closes a Windows handle. This bridges Windows code that calls
// syscall.Close(Handle) to the wasip1 Close(int). The compiler transforms
// syscall.Close() → syscall.CloseW() in Windows-tagged files.
func CloseW(fd Handle) error {
	return Close(int(fd))
}

// Overlapped mirrors Windows OVERLAPPED structure for async I/O.
type Overlapped struct {
	Internal     uintptr
	InternalHigh uintptr
	Offset       uint32
	OffsetHigh   uint32
	HEvent       Handle
}

const (
	INFINITE = 0xffffffff

	FILE_FLAG_BACKUP_SEMANTICS   = 0x02000000
	FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
	FILE_FLAG_OVERLAPPED         = 0x40000000

	ERROR_BROKEN_PIPE = Errno(109)

	PROCESS_TERMINATE         = 1
	PROCESS_QUERY_INFORMATION = 0x00000400

	MAX_PATH = 260

	STANDARD_RIGHTS_REQUIRED = 0x000F0000
	STANDARD_RIGHTS_READ     = 0x00020000
	STANDARD_RIGHTS_WRITE    = 0x00020000
	STANDARD_RIGHTS_EXECUTE  = 0x00020000
)

// --- I/O functions ---

var (
	procReadFile                 = modkernel32_reg.NewProc("ReadFile")
	procWriteFile                = modkernel32_reg.NewProc("WriteFile")
	procFlushFileBuffers         = modkernel32_reg.NewProc("FlushFileBuffers")
	procCreateFileW              = modkernel32_reg.NewProc("CreateFileW")
	procOpenProcess              = modkernel32_reg.NewProc("OpenProcess")
	procOpenProcessToken         = modadvapi32.NewProc("OpenProcessToken")
	procGetTokenInfo             = modadvapi32.NewProc("GetTokenInformation")
	procGetCurrentProcess        = modkernel32_reg.NewProc("GetCurrentProcess")
	procCreateToolhelp32Snapshot = modkernel32_reg.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modkernel32_reg.NewProc("Process32FirstW")
	procProcess32NextW           = modkernel32_reg.NewProc("Process32NextW")
)

// ReadFile reads data from a file handle, optionally with overlapped I/O.
func ReadFile(fd Handle, p []byte, done *uint32, overlapped *Overlapped) error {
	var _p0 *byte
	if len(p) > 0 {
		_p0 = &p[0]
	}
	r1, _, e1 := SyscallN(procReadFile.Addr(), uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(len(p)), uintptr(unsafe.Pointer(done)), uintptr(unsafe.Pointer(overlapped)))
	if r1 == 0 {
		return Errno(e1)
	}
	return nil
}

// WriteFile writes data to a file handle, optionally with overlapped I/O.
func WriteFile(fd Handle, p []byte, done *uint32, overlapped *Overlapped) error {
	var _p0 *byte
	if len(p) > 0 {
		_p0 = &p[0]
	}
	r1, _, e1 := SyscallN(procWriteFile.Addr(), uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(len(p)), uintptr(unsafe.Pointer(done)), uintptr(unsafe.Pointer(overlapped)))
	if r1 == 0 {
		return Errno(e1)
	}
	return nil
}

// FlushFileBuffers flushes the buffers of a file handle.
func FlushFileBuffers(handle Handle) error {
	r1, _, e1 := SyscallN(procFlushFileBuffers.Addr(), uintptr(handle))
	if r1 == 0 {
		return Errno(e1)
	}
	return nil
}

// CreateFile creates or opens a file or device.
func CreateFile(name *uint16, access uint32, mode uint32, sa *SecurityAttributes, createmode uint32, attrs uint32, templatefile int32) (handle Handle, err error) {
	r0, _, e1 := SyscallN(procCreateFileW.Addr(), uintptr(unsafe.Pointer(name)), uintptr(access), uintptr(mode), uintptr(unsafe.Pointer(sa)), uintptr(createmode), uintptr(attrs), uintptr(templatefile))
	handle = Handle(r0)
	if handle == InvalidHandle {
		err = Errno(e1)
	}
	return
}

// --- Process types and functions ---

// ProcessEntry32 describes an entry from a snapshot of the processes in the system.
type ProcessEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [MAX_PATH]uint16
}

type ProcessInformation struct {
	Process   Handle
	Thread    Handle
	ProcessId uint32
	ThreadId  uint32
}

// OpenProcess opens an existing local process object.
func OpenProcess(da uint32, inheritHandle bool, pid uint32) (handle Handle, err error) {
	var _p0 uint32
	if inheritHandle {
		_p0 = 1
	}
	r0, _, e1 := SyscallN(procOpenProcess.Addr(), uintptr(da), uintptr(_p0), uintptr(pid))
	handle = Handle(r0)
	if handle == 0 {
		err = Errno(e1)
	}
	return
}

// GetCurrentProcess returns a pseudohandle for the current process.
func GetCurrentProcess() (Handle, error) {
	r0, _, e1 := SyscallN(procGetCurrentProcess.Addr())
	if r0 == 0 {
		return 0, Errno(e1)
	}
	return Handle(r0), nil
}

// --- Token/security types and functions ---

// SID is an opaque security identifier.
type SID struct{}

// SIDAndAttributes represents a SID and its attributes.
type SIDAndAttributes struct {
	Sid        *SID
	Attributes uint32
}

// Token represents an access token handle.
type Token Handle

// Tokenuser represents the user account of the token.
type Tokenuser struct {
	User SIDAndAttributes
}

// Tokenprimarygroup represents the primary group of the token.
type Tokenprimarygroup struct {
	PrimaryGroup *SID
}

const (
	// Token access rights.
	TOKEN_ASSIGN_PRIMARY    = 0x0001
	TOKEN_DUPLICATE         = 0x0002
	TOKEN_IMPERSONATE       = 0x0004
	TOKEN_QUERY             = 0x0008
	TOKEN_QUERY_SOURCE      = 0x0010
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_ADJUST_GROUPS     = 0x0040
	TOKEN_ADJUST_DEFAULT    = 0x0080
	TOKEN_ADJUST_SESSIONID  = 0x0100

	TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
		TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE |
		TOKEN_IMPERSONATE |
		TOKEN_QUERY |
		TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES |
		TOKEN_ADJUST_GROUPS |
		TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID

	TOKEN_READ    = STANDARD_RIGHTS_READ | TOKEN_QUERY
	TOKEN_WRITE   = STANDARD_RIGHTS_WRITE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT
	TOKEN_EXECUTE = STANDARD_RIGHTS_EXECUTE

	// Token information classes.
	TokenUser = 1 + iota
	TokenGroups
	TokenPrivileges
	TokenOwner
	TokenPrimaryGroup
	TokenDefaultDacl
	TokenSource
	TokenType
	TokenImpersonationLevel
	TokenStatistics
	TokenRestrictedSids
	TokenSessionId
	TokenGroupsAndPrivileges
	TokenSessionReference
	TokenSandBoxInert
	TokenAuditPolicy
	TokenOrigin
	TokenElevationType
	TokenLinkedToken
	TokenElevation
	TokenHasRestrictions
	TokenAccessInformation
	TokenVirtualizationAllowed
	TokenVirtualizationEnabled
	TokenIntegrityLevel
	TokenUIAccess
	TokenMandatoryPolicy
	TokenLogonSid
	MaxTokenInfoClass
)

// OpenProcessToken opens the access token associated with a process.
func OpenProcessToken(h Handle, access uint32, token *Token) error {
	r1, _, e1 := SyscallN(procOpenProcessToken.Addr(), uintptr(h), uintptr(access), uintptr(unsafe.Pointer(token)))
	if r1 == 0 {
		return Errno(e1)
	}
	return nil
}

// GetTokenInformation retrieves information about an access token.
func GetTokenInformation(t Token, infoClass uint32, info *byte, infoLen uint32, returnedLen *uint32) error {
	r1, _, e1 := SyscallN(procGetTokenInfo.Addr(), uintptr(t), uintptr(infoClass), uintptr(unsafe.Pointer(info)), uintptr(infoLen), uintptr(unsafe.Pointer(returnedLen)))
	if r1 == 0 {
		return Errno(e1)
	}
	return nil
}

// Token.Close releases access to the token.
func (t Token) Close() error {
	return CloseHandle(Handle(t))
}

// --- Process snapshot functions ---

// CreateToolhelp32Snapshot takes a snapshot of specified processes.
func CreateToolhelp32Snapshot(flags uint32, processId uint32) (handle Handle, err error) {
	r0, _, e1 := SyscallN(procCreateToolhelp32Snapshot.Addr(), uintptr(flags), uintptr(processId))
	handle = Handle(r0)
	if handle == InvalidHandle {
		err = Errno(e1)
	}
	return
}

// Process32First retrieves information about the first process in a snapshot.
func Process32First(snapshot Handle, procEntry *ProcessEntry32) error {
	r1, _, e1 := SyscallN(procProcess32FirstW.Addr(), uintptr(snapshot), uintptr(unsafe.Pointer(procEntry)))
	if r1 == 0 {
		return Errno(e1)
	}
	return nil
}

// Process32Next retrieves information about the next process in a snapshot.
func Process32Next(snapshot Handle, procEntry *ProcessEntry32) error {
	r1, _, e1 := SyscallN(procProcess32NextW.Addr(), uintptr(snapshot), uintptr(unsafe.Pointer(procEntry)))
	if r1 == 0 {
		return Errno(e1)
	}
	return nil
}

// --- Toolhelp32 snapshot constants ---

const (
	TH32CS_SNAPHEAPLIST = 0x01
	TH32CS_SNAPPROCESS  = 0x02
	TH32CS_SNAPTHREAD   = 0x04
	TH32CS_SNAPMODULE   = 0x08
	TH32CS_SNAPMODULE32 = 0x10
	TH32CS_SNAPALL      = TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD
	TH32CS_INHERIT      = 0x80000000
)

// --- File creation mode constants ---

const (
	CREATE_NEW        = 1
	CREATE_ALWAYS     = 2
	OPEN_EXISTING     = 3
	OPEN_ALWAYS       = 4
	TRUNCATE_EXISTING = 5
)

// --- WSA/Winsock types and functions ---

// Winsock error codes (from syscall/types_windows.go).
const (
	WSAEACCES       Errno = 10013
	WSAENOPROTOOPT  Errno = 10042
	WSAECONNABORTED Errno = 10053
	WSAECONNRESET   Errno = 10054
)

type WSABuf struct {
	Len uint32
	Buf *byte
}

var procAcceptEx = modmswsock.NewProc("AcceptEx")
var procWSARecv = modws2_32.NewProc("WSARecv")
var procWSASend = modws2_32.NewProc("WSASend")

var modmswsock = NewLazyDLL("mswsock.dll")
var modws2_32 = NewLazyDLL("ws2_32.dll")

func AcceptEx(ls Handle, as Handle, buf *byte, rxdatalen uint32, laddrlen uint32, raddrlen uint32, recvd *uint32, overlapped *Overlapped) error {
	r1, _, e1 := SyscallN(procAcceptEx.Addr(),
		uintptr(ls), uintptr(as), uintptr(unsafe.Pointer(buf)),
		uintptr(rxdatalen), uintptr(laddrlen), uintptr(raddrlen),
		uintptr(unsafe.Pointer(recvd)), uintptr(unsafe.Pointer(overlapped)))
	if r1 == 0 {
		return Errno(e1)
	}
	return nil
}

func WSARecv(s Handle, bufs *WSABuf, bufcnt uint32, recvd *uint32, flags *uint32, overlapped *Overlapped, croutine *byte) error {
	r1, _, e1 := SyscallN(procWSARecv.Addr(),
		uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt),
		uintptr(unsafe.Pointer(recvd)), uintptr(unsafe.Pointer(flags)),
		uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)))
	if r1 != 0 {
		return Errno(e1)
	}
	return nil
}

func WSASend(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, overlapped *Overlapped, croutine *byte) error {
	r1, _, e1 := SyscallN(procWSASend.Addr(),
		uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt),
		uintptr(unsafe.Pointer(sent)), uintptr(flags),
		uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)))
	if r1 != 0 {
		return Errno(e1)
	}
	return nil
}

// --- SID methods ---

var procLookupAccountSidW = modadvapi32.NewProc("LookupAccountSidW")

func LookupAccountSid(systemName *uint16, sid *SID, name *uint16, nameLen *uint32, refdDomainName *uint16, refdDomainNameLen *uint32, use *uint32) error {
	r1, _, e1 := SyscallN(procLookupAccountSidW.Addr(),
		uintptr(unsafe.Pointer(systemName)),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(nameLen)),
		uintptr(unsafe.Pointer(refdDomainName)),
		uintptr(unsafe.Pointer(refdDomainNameLen)),
		uintptr(unsafe.Pointer(use)))
	if r1 == 0 {
		return Errno(e1)
	}
	return nil
}

func (sid *SID) LookupAccount(system string) (account, domain string, accType uint32, err error) {
	var sys *uint16
	if len(system) > 0 {
		sys, err = UTF16PtrFromString(system)
		if err != nil {
			return "", "", 0, err
		}
	}
	n := uint32(50)
	dn := uint32(50)
	for {
		b := make([]uint16, n)
		db := make([]uint16, dn)
		e := LookupAccountSid(sys, sid, &b[0], &n, &db[0], &dn, &accType)
		if e == nil {
			return UTF16ToString(b), UTF16ToString(db), accType, nil
		}
		if e != ERROR_INSUFFICIENT_BUFFER {
			return "", "", 0, e
		}
		if n <= uint32(len(b)) {
			return "", "", 0, e
		}
	}
}
