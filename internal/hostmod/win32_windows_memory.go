//go:build windows

package hostmod

import (
	"context"
	"encoding/binary"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

// win32VirtualAlloc allocates a region of host memory using VirtualAlloc and
// registers it as a handleHostMem entry. The guest handle ID is written to handlePtr.
func win32VirtualAlloc(ctx context.Context, mod api.Module, size, allocType, protect, handlePtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}
	if size == 0 {
		return errnoEINVAL
	}

	addr, err := windows.VirtualAlloc(0, uintptr(size), allocType, protect)
	if err != nil {
		return win32Errno(err)
	}

	id := ht.register(&win32HandleEntry{
		kind:      handleHostMem,
		winHandle: addr,
		memSize:   uintptr(size),
	})

	if !writeInt32(mod, handlePtr, id) {
		_ = windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32VirtualProtect changes the protection on a host memory allocation.
// The previous protection is written to oldProtectPtr.
func win32VirtualProtect(ctx context.Context, mod api.Module, handle int32, newProtect, oldProtectPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil || entry.kind != handleHostMem {
		return errnoEBADF
	}

	var oldProtect uint32
	if err := windows.VirtualProtect(entry.winHandle, entry.memSize, newProtect, &oldProtect); err != nil {
		return win32Errno(err)
	}

	if !writeUint32(mod, oldProtectPtr, oldProtect) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32VirtualFree releases a host memory allocation created by win32VirtualAlloc.
func win32VirtualFree(ctx context.Context, mod api.Module, handle int32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.remove(handle)
	if entry == nil || entry.kind != handleHostMem {
		return errnoEBADF
	}

	if err := windows.VirtualFree(entry.winHandle, 0, windows.MEM_RELEASE); err != nil {
		return win32Errno(err)
	}
	return errnoSuccess
}

// win32HMemWrite copies bytes from WASM memory into a host memory allocation.
// offset+dataLen must not exceed the allocation size.
func win32HMemWrite(ctx context.Context, mod api.Module, handle int32, offset, dataPtr, dataLen uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil || entry.kind != handleHostMem {
		return errnoEBADF
	}

	if uintptr(offset)+uintptr(dataLen) > entry.memSize {
		return errnoERANGE
	}

	data, ok := readBytes(mod, dataPtr, dataLen)
	if !ok {
		return errnoEFAULT
	}

	dst := (*[1 << 30]byte)(unsafe.Pointer(entry.winHandle + uintptr(offset)))[:dataLen]
	copy(dst, data)
	return errnoSuccess
}

// win32HMemRead copies bytes from a host memory allocation into WASM memory.
// offset+bufLen must not exceed the allocation size.
func win32HMemRead(ctx context.Context, mod api.Module, handle int32, offset, bufPtr, bufLen uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil || entry.kind != handleHostMem {
		return errnoEBADF
	}

	if uintptr(offset)+uintptr(bufLen) > entry.memSize {
		return errnoERANGE
	}

	src := (*[1 << 30]byte)(unsafe.Pointer(entry.winHandle + uintptr(offset)))[:bufLen]
	tmp := make([]byte, bufLen)
	copy(tmp, src)

	if !writeBytes(mod, bufPtr, tmp) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32HMemWrite32 writes a uint32 value at offset within a host memory allocation.
func win32HMemWrite32(ctx context.Context, mod api.Module, handle int32, offset, value uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil || entry.kind != handleHostMem {
		return errnoEBADF
	}

	if uintptr(offset)+4 > entry.memSize {
		return errnoERANGE
	}

	*(*uint32)(unsafe.Pointer(entry.winHandle + uintptr(offset))) = value
	return errnoSuccess
}

// win32HMemWrite64 reads 8 bytes from WASM memory at valPtr and writes them as
// a uint64 at offset within a host memory allocation (little-endian).
func win32HMemWrite64(ctx context.Context, mod api.Module, handle int32, offset, valPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil || entry.kind != handleHostMem {
		return errnoEBADF
	}

	if uintptr(offset)+8 > entry.memSize {
		return errnoERANGE
	}

	raw, ok := readBytes(mod, valPtr, 8)
	if !ok {
		return errnoEFAULT
	}

	val := binary.LittleEndian.Uint64(raw)
	*(*uint64)(unsafe.Pointer(entry.winHandle + uintptr(offset))) = val
	return errnoSuccess
}

// win32HMemRead32 reads a uint32 from offset within a host memory allocation
// and writes it to valPtr in WASM memory (little-endian).
func win32HMemRead32(ctx context.Context, mod api.Module, handle int32, offset, valPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil || entry.kind != handleHostMem {
		return errnoEBADF
	}

	if uintptr(offset)+4 > entry.memSize {
		return errnoERANGE
	}

	val := *(*uint32)(unsafe.Pointer(entry.winHandle + uintptr(offset)))
	if !writeUint32(mod, valPtr, val) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32HMemRead64 reads a uint64 from offset within a host memory allocation
// and writes it as 8 little-endian bytes to valPtr in WASM memory.
func win32HMemRead64(ctx context.Context, mod api.Module, handle int32, offset, valPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil || entry.kind != handleHostMem {
		return errnoEBADF
	}

	if uintptr(offset)+8 > entry.memSize {
		return errnoERANGE
	}

	val := *(*uint64)(unsafe.Pointer(entry.winHandle + uintptr(offset)))
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], val)
	if !writeBytes(mod, valPtr, buf[:]) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32ProcFromHMem registers the address at hostmem+offset as a callable proc
// handle. This allows calling code in host memory (shellcode, PE entry points)
// via SyscallN. The new proc handle is written to procPtr.
func win32ProcFromHMem(ctx context.Context, mod api.Module, hmemHandle int32, offset, procPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(hmemHandle)
	if entry == nil || entry.kind != handleHostMem {
		return errnoEBADF
	}

	if uintptr(offset) >= entry.memSize {
		return errnoERANGE
	}

	addr := entry.winHandle + uintptr(offset)
	id := ht.register(&win32HandleEntry{
		kind:     handleProc,
		procAddr: addr,
	})

	if !writeInt32(mod, procPtr, id) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32ProcAddr returns the real host address of a proc handle as a little-endian
// uint64 written to addrPtr. This is needed for writing resolved function addresses
// into PE import address tables in host memory.
func win32ProcAddr(ctx context.Context, mod api.Module, procHandle int32, addrPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(procHandle)
	if entry == nil || entry.kind != handleProc {
		return errnoEBADF
	}

	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(entry.procAddr))
	if !writeBytes(mod, addrPtr, buf[:]) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32HMemAddr writes the real host address of the allocation as a little-endian
// uint64 to addrPtr in WASM memory. This allows passing the address to SyscallN.
func win32HMemAddr(ctx context.Context, mod api.Module, handle int32, addrPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}

	ht := getWin32Handles(ctx)
	if ht != nil {
		entry := ht.get(handle)
		if entry != nil && entry.kind == handleHostMem {
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], uint64(entry.winHandle))
			if !writeBytes(mod, addrPtr, buf[:]) {
				return errnoEFAULT
			}
			return errnoSuccess
		}
	}

	if sm := getShadowMap(ctx); sm != nil {
		wasmAddr := uint32(handle)
		if entry := sm.LookupContaining(wasmAddr); entry != nil {
			offset := uintptr(wasmAddr - entry.wasmAddr)
			hostAddr := entry.hostAddr + offset

			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], uint64(hostAddr))
			if !writeBytes(mod, addrPtr, buf[:]) {
				return errnoEFAULT
			}
			return errnoSuccess
		}
	}

	if ht == nil {
		return errnoEINVAL
	}
	return errnoEBADF
}
