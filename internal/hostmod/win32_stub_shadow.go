//go:build !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// shadowVirtualAlloc always returns errnoENOSYS on non-Windows platforms.
func shadowVirtualAlloc(ctx context.Context, mod api.Module, wasmAddr, size, allocType, protect uint32) uint32 {
	return errnoENOSYS
}

// shadowVirtualProtect always returns errnoENOSYS on non-Windows platforms.
func shadowVirtualProtect(ctx context.Context, mod api.Module, wasmAddr, size, newProtect, oldProtectPtr uint32) uint32 {
	return errnoENOSYS
}

// shadowVirtualFree always returns errnoENOSYS on non-Windows platforms.
func shadowVirtualFree(ctx context.Context, mod api.Module, wasmAddr, size, freeType uint32) uint32 {
	return errnoENOSYS
}

// shadowGetHostAddr always returns errnoENOSYS on non-Windows platforms.
func shadowGetHostAddr(ctx context.Context, mod api.Module, wasmAddr, addrPtr uint32) uint32 {
	return errnoENOSYS
}

// shadowCallEntry always returns errnoENOSYS on non-Windows platforms.
func shadowCallEntry(ctx context.Context, mod api.Module, wasmAddr, entryOffset, fdwReason, resultPtr uint32) uint32 {
	return errnoENOSYS
}
