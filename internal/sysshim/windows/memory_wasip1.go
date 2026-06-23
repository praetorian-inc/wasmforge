// Shadow memory support for wasip1.
// VirtualAlloc allocates in both WASM linear memory (via make([]byte, size))
// and real host memory (via shadow_virtual_alloc host function). The returned
// uintptr points into WASM linear memory and is usable with unsafe.Pointer.

//go:build wasip1

package windows

import (
	"sync"
	"syscall"
	"unsafe"
)

// Memory allocation type constants.
const (
	MEM_COMMIT      = 0x00001000
	MEM_RESERVE     = 0x00002000
	MEM_DECOMMIT    = 0x00004000
	MEM_RELEASE     = 0x00008000
	MEM_RESET       = 0x00080000
	MEM_TOP_DOWN    = 0x00100000
	MEM_WRITE_WATCH = 0x00200000
	MEM_PHYSICAL    = 0x00400000
	MEM_RESET_UNDO  = 0x01000000
	MEM_LARGE_PAGES = 0x20000000
)

// Memory protection constants.
const (
	PAGE_NOACCESS          = 0x00000001
	PAGE_READONLY          = 0x00000002
	PAGE_READWRITE         = 0x00000004
	PAGE_WRITECOPY         = 0x00000008
	PAGE_EXECUTE           = 0x00000010
	PAGE_EXECUTE_READ      = 0x00000020
	PAGE_EXECUTE_READWRITE = 0x00000040
	PAGE_EXECUTE_WRITECOPY = 0x00000080
	PAGE_GUARD             = 0x00000100
	PAGE_NOCACHE           = 0x00000200
	PAGE_WRITECOMBINE      = 0x00000400
	PAGE_TARGETS_INVALID   = 0x40000000
	PAGE_TARGETS_NO_UPDATE = 0x40000000

	QUOTA_LIMITS_HARDWS_MIN_DISABLE = 0x00000002
	QUOTA_LIMITS_HARDWS_MIN_ENABLE  = 0x00000001
	QUOTA_LIMITS_HARDWS_MAX_DISABLE = 0x00000008
	QUOTA_LIMITS_HARDWS_MAX_ENABLE  = 0x00000004
)

// MemoryBasicInformation contains information about a range of pages.
type MemoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

// shadowKeepAlive prevents GC from collecting the WASM-side backing slices.
// NOTE: This is a package-level global, so it assumes a single WASM module
// instance per host process. If multiple instances run concurrently, their
// WASM address spaces could overlap and a VirtualFree in one instance could
// remove the keepalive for another. This matches wasmforge's current single-
// instance execution model.
var shadowKeepAlive sync.Map // wasmAddr (uintptr) → []byte

// VirtualAlloc allocates memory in both WASM linear memory and real host memory.
// The returned uintptr is within WASM's address space and can be used with
// unsafe.Pointer for direct reads/writes.
func VirtualAlloc(address uintptr, size uintptr, alloctype uint32, protect uint32) (uintptr, error) {
	// Sub-commits within an existing reservation reuse the shadow allocation.
	if address != 0 && (alloctype&MEM_RESERVE) == 0 {
		return address, nil
	}

	// Allocate a byte slice in WASM linear memory. This gives us an address
	// within the WASM address space that can be used with unsafe.Pointer.
	shadow := make([]byte, size)
	wasmAddr := uintptr(unsafe.Pointer(&shadow[0]))

	// Ask the host to create a real VirtualAlloc allocation and register
	// the shadow mapping between wasmAddr and the host allocation.
	errno := syscall.ShadowVirtualAlloc(uint32(wasmAddr), uint32(size), alloctype, protect)
	if errno != 0 {
		return 0, syscall.Errno(errno)
	}

	// Prevent the backing slice from being garbage collected.
	shadowKeepAlive.Store(wasmAddr, shadow)

	return wasmAddr, nil
}

// VirtualProtect changes the protection on a shadow memory allocation.
// The host syncs WASM↔Host memory as part of this call.
func VirtualProtect(address uintptr, size uintptr, newprotect uint32, oldprotect *uint32) error {
	errno := syscall.ShadowVirtualProtect(
		uint32(address),
		uint32(size),
		newprotect,
		uint32(uintptr(unsafe.Pointer(oldprotect))),
	)
	if errno != 0 {
		return syscall.Errno(errno)
	}
	return nil
}

// VirtualFree releases a shadow memory allocation.
func VirtualFree(address uintptr, size uintptr, freetype uint32) error {
	errno := syscall.ShadowVirtualFree(uint32(address), uint32(size), freetype)
	if errno != 0 {
		return syscall.Errno(errno)
	}
	// Allow the WASM-side backing slice to be GC'd.
	shadowKeepAlive.Delete(address)
	return nil
}

// VirtualQuery is a stub that returns basic information about a shadow allocation.
func VirtualQuery(address uintptr, buffer *MemoryBasicInformation, length uintptr) error {
	return syscall.ENOSYS
}

// HostMemoryAddress returns the host address for a host memory handle or WASM
// shadow allocation.
func HostMemoryAddress(handleOrAddr uintptr) (uintptr, error) {
	var buf [8]byte
	errno := syscall.HostMemoryAddress(uint32(handleOrAddr), uint32(uintptr(unsafe.Pointer(&buf[0]))))
	if errno != 0 {
		return 0, syscall.Errno(errno)
	}
	addr := uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
		uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56
	return uintptr(addr), nil
}
