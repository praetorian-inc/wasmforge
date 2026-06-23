//go:build windows

package hostmod

import (
	"context"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

// shadowVirtualAlloc allocates real host memory via VirtualAlloc and registers
// a shadow mapping between the given WASM address and the host allocation.
// The guest has already allocated a []byte in WASM linear memory at wasmAddr;
// this function creates the corresponding host-side allocation.
func shadowVirtualAlloc(ctx context.Context, mod api.Module, wasmAddr, size, allocType, protect uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	sm := getShadowMap(ctx)
	if sm == nil {
		return errnoEINVAL
	}
	if size == 0 {
		return errnoEINVAL
	}

	hostAddr, err := windows.VirtualAlloc(0, uintptr(size), allocType, protect)
	if err != nil {
		return win32Errno(err)
	}

	sm.Register(wasmAddr, hostAddr, size, protect)
	return errnoSuccess
}

// shadowVirtualProtect changes the protection on a shadow allocation.
// It syncs WASM→Host (pre-sync), calls real VirtualProtect, and writes
// the old protection value to oldProtectPtr.
//
// Because the host memory may currently have a non-writable protection
// (e.g. PAGE_READONLY, PAGE_EXECUTE_READ), we temporarily make it
// PAGE_READWRITE for the pre-sync copy.
func shadowVirtualProtect(ctx context.Context, mod api.Module, wasmAddr, size, newProtect, oldProtectPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	sm := getShadowMap(ctx)
	if sm == nil {
		return errnoEINVAL
	}
	if size == 0 {
		return errnoEINVAL
	}

	entry := sm.LookupContaining(wasmAddr)
	if entry == nil {
		return errnoEBADF
	}

	if wasmAddr+size > entry.wasmAddr+entry.size {
		return errnoEINVAL
	}

	// Temporarily make host memory writable for the pre-sync copy.
	// The current protection may not allow writes (e.g. PAGE_READONLY).
	var tmpOldProtect uint32
	if entry.protect != windows.PAGE_READWRITE && entry.protect != windows.PAGE_EXECUTE_READWRITE {
		if err := windows.VirtualProtect(entry.hostAddr, uintptr(entry.size),
			windows.PAGE_READWRITE, &tmpOldProtect); err != nil {
			return win32Errno(err)
		}
	}

	// Pre-sync: copy WASM → Host (full allocation).
	wasmData, ok := readBytes(mod, entry.wasmAddr, entry.size)
	if !ok {
		return errnoEFAULT
	}
	hostSlice := unsafe.Slice((*byte)(unsafe.Pointer(entry.hostAddr)), entry.size)
	copy(hostSlice, wasmData)

	// Call real VirtualProtect on the translated host address.
	offset := uintptr(wasmAddr - entry.wasmAddr)
	hostTargetAddr := entry.hostAddr + offset
	var oldProtect uint32
	if err := windows.VirtualProtect(hostTargetAddr, uintptr(size), newProtect, &oldProtect); err != nil {
		return win32Errno(err)
	}

	// Write the tracked old protection to WASM memory. We use entry.protect
	// (what the guest last set) rather than oldProtect (which may reflect our
	// temporary PAGE_READWRITE).
	if !writeUint32(mod, oldProtectPtr, entry.protect) {
		return errnoEFAULT
	}

	// Update the entry's protection.
	sm.UpdateProtect(entry.wasmAddr, newProtect)

	return errnoSuccess
}

// shadowGetHostAddr writes the host address for a WASM shadow allocation.
func shadowGetHostAddr(ctx context.Context, mod api.Module, wasmAddr, addrPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	sm := getShadowMap(ctx)
	if sm == nil {
		return errnoEINVAL
	}

	entry := sm.LookupContaining(wasmAddr)
	if entry == nil {
		return errnoEBADF
	}

	offset := uintptr(wasmAddr - entry.wasmAddr)
	hostAddr := entry.hostAddr + offset

	var buf [8]byte
	buf[0] = byte(hostAddr)
	buf[1] = byte(hostAddr >> 8)
	buf[2] = byte(hostAddr >> 16)
	buf[3] = byte(hostAddr >> 24)
	buf[4] = byte(hostAddr >> 32)
	buf[5] = byte(hostAddr >> 40)
	buf[6] = byte(hostAddr >> 48)
	buf[7] = byte(hostAddr >> 56)

	if !writeBytes(mod, addrPtr, buf[:]) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// shadowCallEntry syncs the allocation and calls DllMain in host memory.
func shadowCallEntry(ctx context.Context, mod api.Module, wasmAddr, entryOffset, fdwReason, resultPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	sm := getShadowMap(ctx)
	if sm == nil {
		return errnoEINVAL
	}

	entry := sm.LookupContaining(wasmAddr)
	if entry == nil {
		return errnoEBADF
	}

	if uintptr(entryOffset) >= uintptr(entry.size) {
		return errnoERANGE
	}

	// Temporarily allow both the sync copy and entry point execution.
	var oldProtect uint32
	if err := windows.VirtualProtect(entry.hostAddr, uintptr(entry.size),
		windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return win32Errno(err)
	}

	// Sync WASM → Host (full allocation).
	wasmData, ok := readBytes(mod, entry.wasmAddr, entry.size)
	if !ok {
		return errnoEFAULT
	}
	hostSlice := unsafe.Slice((*byte)(unsafe.Pointer(entry.hostAddr)), entry.size)
	copy(hostSlice, wasmData)

	// Flush instruction cache after writing code.
	flushInstructionCache(entry.hostAddr, uintptr(entry.size))

	// Call the entry point: DllMain(hinstDLL, fdwReason, lpvReserved)
	hostEntry := entry.hostAddr + uintptr(entryOffset)
	r0, _, _ := syscall.SyscallN(hostEntry, entry.hostAddr, uintptr(fdwReason), 0)

	if !writeUint32(mod, resultPtr, uint32(r0)) {
		return errnoEFAULT
	}
	return errnoSuccess
}

var procFlushInstructionCache = windows.NewLazySystemDLL("kernel32.dll").NewProc("FlushInstructionCache")

func flushInstructionCache(addr uintptr, size uintptr) {
	currentProcess, _ := syscall.GetCurrentProcess()
	procFlushInstructionCache.Call(uintptr(currentProcess), addr, size)
}

// shadowVirtualFree releases a shadow allocation. Atomically removes the
// shadow map entry and frees the real host memory.
func shadowVirtualFree(ctx context.Context, mod api.Module, wasmAddr, size, freeType uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	sm := getShadowMap(ctx)
	if sm == nil {
		return errnoEINVAL
	}

	// Atomic lookup+remove to avoid TOCTOU races.
	entry := sm.Remove(wasmAddr)
	if entry == nil {
		return errnoEBADF
	}

	if err := windows.VirtualFree(entry.hostAddr, 0, windows.MEM_RELEASE); err != nil {
		return win32Errno(err)
	}

	return errnoSuccess
}
