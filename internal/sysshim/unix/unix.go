// Package unix provides minimal stubs of golang.org/x/sys/unix for wasip1.
// Only functions actually exercised by validated guests are implemented;
// adding more is mechanical when a new caller surfaces.

//go:build wasip1

package unix

import "os"

// Utsname mirrors the C struct utsname. Real x/sys/unix uses [256]int8 but we
// use [256]byte for simplicity — functionally equivalent via ByteSliceToString.
type Utsname struct {
	Sysname    [256]byte
	Nodename   [256]byte
	Release    [256]byte
	Version    [256]byte
	Machine    [256]byte
	Domainname [256]byte
}

// Uname populates buf with system identification.
func Uname(buf *Utsname) error {
	copyField := func(dst *[256]byte, s string) {
		n := copy(dst[:len(dst)-1], s)
		dst[n] = 0
	}

	copyField(&buf.Sysname, "Darwin")

	hostname, err := os.Hostname()
	if err == nil {
		copyField(&buf.Nodename, hostname)
	} else {
		copyField(&buf.Nodename, "unknown")
	}

	copyField(&buf.Release, "24.0.0")
	copyField(&buf.Version, "WasmForge")
	copyField(&buf.Machine, "x86_64")
	return nil
}

// ByteSliceToString returns a string from a null-terminated byte slice.
func ByteSliceToString(s []byte) string {
	for i, b := range s {
		if b == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}
