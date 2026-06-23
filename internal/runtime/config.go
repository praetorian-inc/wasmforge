// Package runtime provides the wazero-based WASM execution environment
// for wasmforge-compiled programs.
package runtime

import (
	"io"
)

// Config holds runtime configuration for executing a WASM module.
type Config struct {
	// WASMData is the compiled WASM module bytes.
	WASMData []byte

	// Args are the command-line arguments (os.Args style).
	Args []string

	// Env are the environment variables.
	Env []string

	// Stdio.
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader

	// RawSockets enables raw socket (SOCK_RAW) creation.
	RawSockets bool

	// Win32APIs enables Win32 API host functions.
	Win32APIs bool

	// DarwinAPIs enables Darwin/macOS framework host functions.
	DarwinAPIs bool

	// NoAMSIPatch disables the AMSI patch. Use for Go payloads that don't
	// need CLR Assembly.Load and want to avoid behavioral AMSI-bypass alerts.
	NoAMSIPatch bool

	// FSMounts lists host directories to mount into the WASM filesystem.
	// Format: "hostpath:guestpath" or just "hostpath" (mounted at same path).
	FSMounts []string

	// NetworkPolicy defines network access rules (nil = allow all).
	NetworkPolicy *NetworkPolicy
}
