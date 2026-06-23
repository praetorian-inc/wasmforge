// Package patch handles patching a copied GOROOT with wasmforge
// networking-enabled replacement files.
package patch

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed files/*
var patchFiles embed.FS

// PatchOptions controls which patches are applied.
type PatchOptions struct {
	// Win32APIs applies the Win32 syscall shim patch, enabling
	// golang.org/x/sys/windows to work on wasip1.
	Win32APIs bool
}

// Patch describes a single file replacement.
type Patch struct {
	// EmbedName is the filename within the embedded files/ directory.
	EmbedName string
	// TargetPath is the relative path within GOROOT/src to replace.
	TargetPath string
	// Condition gates the patch: "" means always apply, "win32" means
	// only apply when PatchOptions.Win32APIs is true.
	Condition string
}

// Patches returns the list of stdlib files to replace.
func Patches() []Patch {
	return []Patch{
		// Networking patches (always applied).
		{
			EmbedName:  "syscall_net_wasip1.go",
			TargetPath: "syscall/net_wasip1.go",
		},
		{
			EmbedName:  "net_net_fake.go",
			TargetPath: "net/net_fake.go",
		},
		{
			EmbedName:  "net_fd_fake.go",
			TargetPath: "net/fd_fake.go",
		},
		{
			EmbedName:  "net_sockopt_fake.go",
			TargetPath: "net/sockopt_fake.go",
		},

		// OS host function patches (always applied).
		{
			EmbedName:  "os_sys_wasip1_host.go",
			TargetPath: "os/sys_wasip1_host.go",
		},
		{
			EmbedName:  "net_interface_host.go",
			TargetPath: "net/interface_host.go",
		},
		{
			EmbedName:  "os_user_lookup_wasip1.go",
			TargetPath: "os/user/lookup_wasip1.go",
		},
		{
			EmbedName:  "syscall_os_wasip1.go",
			TargetPath: "syscall/syscall_os_wasip1.go",
		},

		// os/exec fallback for wasip1 (always applied).
		{
			EmbedName:  "exec_wasip1.go",
			TargetPath: "os/exec/exec_wasip1.go",
		},

		// Pipe support for wasip1 (always applied).
		{
			EmbedName:  "syscall_pipe_wasip1.go",
			TargetPath: "syscall/syscall_pipe_wasip1.go",
		},

		// Win32 syscall shim (only with Win32APIs option).
		{
			EmbedName:  "syscall_win32_wasip1.go",
			TargetPath: "syscall/syscall_win32_wasip1.go",
			Condition:  "win32",
		},
	}
}

// Fingerprint returns a stable digest of the embedded replacement files that
// apply for opts. Build caches include this so stdlib shim edits invalidate
// stale patched GOROOT directories.
func Fingerprint(opts PatchOptions) (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "win32=%t\n", opts.Win32APIs)

	for _, p := range Patches() {
		if p.Condition == "win32" && !opts.Win32APIs {
			continue
		}
		content, err := patchFiles.ReadFile("files/" + p.EmbedName)
		if err != nil {
			return "", fmt.Errorf("reading embedded patch %s: %w", p.EmbedName, err)
		}
		fmt.Fprintf(h, "%s\x00%s\x00%s\n", p.EmbedName, p.TargetPath, p.Condition)
		h.Write(content)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// Apply copies the embedded replacement files over the originals
// in the patched GOROOT, respecting opts to skip conditional patches.
func Apply(gorootSrc string, opts PatchOptions) error {
	for _, p := range Patches() {
		if p.Condition == "win32" && !opts.Win32APIs {
			continue
		}

		content, err := patchFiles.ReadFile("files/" + p.EmbedName)
		if err != nil {
			return fmt.Errorf("reading embedded patch %s: %w", p.EmbedName, err)
		}

		target := filepath.Join(gorootSrc, p.TargetPath)
		dir := filepath.Dir(target)

		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}

		if err := os.WriteFile(target, content, 0o644); err != nil {
			return fmt.Errorf("writing patched file %s: %w", target, err)
		}
	}

	// Remove wasip1 from build tags that conflict with our patches.
	if err := removeWasip1FromSysBsd(gorootSrc); err != nil {
		return fmt.Errorf("patching sys_bsd.go: %w", err)
	}
	if err := removeWasip1FromInterfaceStub(gorootSrc); err != nil {
		return fmt.Errorf("patching interface_stub.go: %w", err)
	}
	if err := excludeWasip1FromBSDInterface(gorootSrc); err != nil {
		return fmt.Errorf("patching interface_bsd.go: %w", err)
	}
	if err := excludeWasip1FromLookupStubs(gorootSrc); err != nil {
		return fmt.Errorf("patching lookup_stubs.go: %w", err)
	}
	if err := patchGetpid(gorootSrc); err != nil {
		return fmt.Errorf("patching Getpid: %w", err)
	}
	if err := patchGetwdChdir(gorootSrc); err != nil {
		return fmt.Errorf("patching Getwd/Chdir: %w", err)
	}
	if err := patchStartProcessWait4(gorootSrc); err != nil {
		return fmt.Errorf("patching StartProcess/Wait4: %w", err)
	}
	if err := patchPreparePath(gorootSrc); err != nil {
		return fmt.Errorf("patching preparePath: %w", err)
	}
	if err := patchOsGetwd(gorootSrc); err != nil {
		return fmt.Errorf("patching os/getwd.go: %w", err)
	}
	if err := patchExecRun(gorootSrc); err != nil {
		return fmt.Errorf("patching os/exec/exec.go: %w", err)
	}
	if err := patchExecLookPath(gorootSrc); err != nil {
		return fmt.Errorf("patching os/exec/lp_wasm.go: %w", err)
	}
	if err := patchOsPipeWasm(gorootSrc); err != nil {
		return fmt.Errorf("patching os/pipe_wasm.go: %w", err)
	}
	if err := patchSyscallPipe(gorootSrc); err != nil {
		return fmt.Errorf("patching syscall.Pipe: %w", err)
	}
	if err := patchSyscallReadWriteClose(gorootSrc); err != nil {
		return fmt.Errorf("patching syscall Read/Write/Close: %w", err)
	}
	if err := patchOsOpenWasip1(gorootSrc); err != nil {
		return fmt.Errorf("patching os/file_open_wasip1.go: %w", err)
	}
	if err := patchErrnoError(gorootSrc); err != nil {
		return fmt.Errorf("patching Errno.Error(): %w", err)
	}
	if err := patchOsDevNull(gorootSrc); err != nil {
		return fmt.Errorf("patching os.DevNull: %w", err)
	}
	if err := patchNetFakeConstants(gorootSrc); err != nil {
		return fmt.Errorf("patching net_fake.go constants: %w", err)
	}

	// When Win32 mode is enabled, the win32 patch provides Syscall/Syscall6
	// with Windows-compatible signatures (includes nargs parameter). Remove
	// the conflicting declarations from the standard syscall_wasip1.go.
	if opts.Win32APIs {
		if err := removeConflictingSyscalls(gorootSrc); err != nil {
			return fmt.Errorf("removing conflicting syscalls: %w", err)
		}
		if err := patchSysProcAttr(gorootSrc); err != nil {
			return fmt.Errorf("patching SysProcAttr: %w", err)
		}
	}

	return nil
}

// removeConflictingSyscalls removes the Syscall and Syscall6 declarations
// from syscall_wasip1.go when Win32 mode is enabled, since the win32 patch
// provides Windows-compatible versions with an nargs parameter.
func removeConflictingSyscalls(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "syscall", "syscall_wasip1.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Replace the 4-param Syscall with a comment (win32 patch provides 5-param version).
	newContent := strings.Replace(content,
		"func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno) {\n\treturn 0, 0, ENOSYS\n}",
		"// Syscall is provided by syscall_win32_wasip1.go with Windows-compatible nargs parameter.",
		1)
	if newContent == content {
		return fmt.Errorf("removeConflictingSyscalls: Syscall pattern not found in syscall_wasip1.go (possible Go version mismatch)")
	}
	content = newContent

	// Replace the 6-param Syscall6 with a comment (win32 patch provides 8-param version).
	newContent = strings.Replace(content,
		"func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno) {\n\treturn 0, 0, ENOSYS\n}",
		"// Syscall6 is provided by syscall_win32_wasip1.go with Windows-compatible nargs parameter.",
		1)
	if newContent == content {
		return fmt.Errorf("removeConflictingSyscalls: Syscall6 pattern not found in syscall_wasip1.go (possible Go version mismatch)")
	}
	content = newContent

	return os.WriteFile(path, []byte(content), 0o644)
}

// patchSysProcAttr replaces the empty SysProcAttr struct in syscall_wasip1.go
// with a Windows-compatible version that includes Token, HideWindow, and other
// fields needed by programs that create processes with impersonation tokens.
func patchSysProcAttr(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "syscall", "syscall_wasip1.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	newContent := strings.Replace(content,
		"type SysProcAttr struct {\n}",
		`type SysProcAttr struct {
	HideWindow                 bool
	CmdLine                    string
	CreationFlags              uint32
	Token                      Token
	ProcessAttributes          *SecurityAttributes
	ThreadAttributes           *SecurityAttributes
	NoInheritHandles           bool
	AdditionalInheritedHandles []Handle
	ParentProcess              Handle
}`,
		1)
	if newContent == content {
		return fmt.Errorf("patchSysProcAttr: SysProcAttr pattern not found in syscall_wasip1.go (possible Go version mismatch)")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}

// patchNetFakeConstants replaces the iota-based AF_* and socket option constants
// in syscall/net_fake.go with Linux-compatible fixed values.
//
// The original file uses iota which produces:
//   - AF_INET6 = 3 (Linux: 10, macOS: 30)
//   - SO_ERROR = 2 (Linux: 4) — also conflicts with SO_REUSEADDR=2 in syscall_net_wasip1.go
//   - IPV6_V6ONLY = 1 (Linux: 26)
//
// Without this patch, the connect polling loop calls getsockopt(fd, SOL_SOCKET=1,
// SO_ERROR=2) which on macOS resolves to getsockopt(fd, IPPROTO_ICMP, invalid_option),
// causing an error that makes the guest poll forever until timeout.
func patchNetFakeConstants(gorootSrc string) error {
	path := filepath.Join(gorootSrc, "syscall", "net_fake.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Fix AF_* constants to use Linux values instead of iota.
	newContent := strings.Replace(content,
		"const (\n\tAF_UNSPEC = iota\n\tAF_UNIX\n\tAF_INET\n\tAF_INET6\n)",
		"const (\n\tAF_UNSPEC = 0\n\tAF_UNIX   = 1\n\tAF_INET   = 2\n\tAF_INET6  = 10\n)",
		1)

	// Fix SO_ERROR and IPV6_V6ONLY to use Linux values instead of iota.
	newContent = strings.Replace(newContent,
		"const (\n\t_ = iota\n\tIPV6_V6ONLY\n\tSO_ERROR\n)",
		"const (\n\tIPV6_V6ONLY = 26\n\tSO_ERROR    = 4\n)",
		1)

	if newContent == content {
		return fmt.Errorf("patchNetFakeConstants: constants pattern not found in net_fake.go (possible Go version mismatch)")
	}

	return os.WriteFile(path, []byte(newContent), 0o644)
}
