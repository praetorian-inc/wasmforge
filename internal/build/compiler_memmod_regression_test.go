package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for the WASM PE64 / shadow-memmod build transforms
// landed in PR #5. The original break was rooted in a false premise
// (GOARCH=wasm has uintptr=4 — it doesn't, it's 8). These tests pin
// down the transform behaviors that fix the regression so a future
// edit can't silently reintroduce it:
//
//   - arch-suffixed Windows files are filtered to the build target
//     (otherwise foo_windows_amd64.go + foo_windows_arm64.go both
//     survive into the shadow tree and the last write wins)
//   - bitwidth-suffixed Windows files (_windows_64.go) get the
//     build tag relaxed so their PE64 types reach the WASM compile
//   - memmod's three host-only entry points get short-circuited
//   - the relocation delta and DLL entry/detach paths are bridged
//     through ShadowGetHostAddr / ShadowCallEntry (the actual fix
//     for the shadow-memory model)
//   - patchMemmodForWASM does NOT inject struct padding (catches
//     any future re-wiring of padPE64UptrFields, which was the
//     original wrong-headed fix)

func TestWindowsFileArch(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain windows", "foo_windows", ""},
		{"windows amd64", "foo_windows_amd64", "amd64"},
		{"windows arm64", "foo_windows_arm64", "arm64"},
		{"windows 386", "foo_windows_386", "386"},
		{"not arch suffix", "foo_windows_64", ""},
		{"unrelated suffix", "foo_amd64", ""},
		{"no underscore", "windows", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := windowsFileArch(tt.in); got != tt.want {
				t.Errorf("windowsFileArch(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestArchBitwidth(t *testing.T) {
	tests := []struct {
		arch string
		want string
	}{
		{"amd64", "64"},
		{"arm64", "64"},
		{"ppc64le", "64"},
		{"riscv64", "64"},
		{"386", "32"},
		{"arm", "32"},
		{"mipsle", "32"},
		{"", ""},
		{"unknown", ""},
		{"wasm", ""}, // wasm intentionally has no bitwidth bucket
	}
	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			if got := archBitwidth(tt.arch); got != tt.want {
				t.Errorf("archBitwidth(%q) = %q, want %q", tt.arch, got, tt.want)
			}
		})
	}
}

// TestRelaxWindowsBuildConstraints_DisablesArchMismatchedSiblings asserts
// that when targetGOARCH=amd64, foo_windows_arm64.go is renamed with a
// .disabled suffix and foo_windows_amd64.go is kept (renamed to foo.go
// via the standard windows-suffix strip). Without this filter, both
// files survive into the shadow tree and end up redeclaring the same
// symbols with arch-mismatched constants.
func TestRelaxWindowsBuildConstraints_DisablesArchMismatchedSiblings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "foo_windows_amd64.go"), "package main\n\nconst Arch = \"amd64\"\n")
	writeFile(t, filepath.Join(dir, "foo_windows_arm64.go"), "package main\n\nconst Arch = \"arm64\"\n")

	if _, _, err := relaxWindowsBuildConstraints(dir, false, "amd64"); err != nil {
		t.Fatalf("relaxWindowsBuildConstraints: %v", err)
	}

	// amd64 file should have been windows-stripped to foo.go.
	if _, err := os.Stat(filepath.Join(dir, "foo.go")); err != nil {
		t.Errorf("expected foo.go after windows-suffix strip: %v", err)
	}
	// arm64 sibling should be disabled.
	if _, err := os.Stat(filepath.Join(dir, "foo_windows_arm64.go.disabled")); err != nil {
		t.Errorf("expected foo_windows_arm64.go.disabled: %v", err)
	}
	// Original amd64 source name should no longer exist.
	if _, err := os.Stat(filepath.Join(dir, "foo_windows_amd64.go")); !os.IsNotExist(err) {
		t.Errorf("foo_windows_amd64.go should have been renamed away, err=%v", err)
	}
}

// TestRelaxWindowsBuildConstraints_KeepsAllArchFilesWhenNoTarget asserts
// that the arch-filter is opt-in: with no targetGOARCH, both arch files
// survive (existing behavior preserved for non-WASM callers).
func TestRelaxWindowsBuildConstraints_KeepsAllArchFilesWhenNoTarget(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "foo_windows_amd64.go"), "package main\n")
	writeFile(t, filepath.Join(dir, "foo_windows_arm64.go"), "package main\n")

	if _, _, err := relaxWindowsBuildConstraints(dir, false); err != nil {
		t.Fatalf("relaxWindowsBuildConstraints: %v", err)
	}

	// Neither file should be disabled when no target arch is provided.
	if _, err := os.Stat(filepath.Join(dir, "foo_windows_arm64.go.disabled")); err == nil {
		t.Errorf("foo_windows_arm64.go.disabled should NOT exist without targetGOARCH")
	}
}

// TestRelaxWindowsBuildConstraints_RelaxesBitwidthFile asserts that a
// *_windows_64.go file (the bitwidth convention, e.g. memmod's PE64
// struct definitions) gets `|| wasip1` appended to its //go:build tag
// when the target arch is 64-bit. Without this, IMAGE_OPTIONAL_HEADER
// and friends never compile for the WASM target and the resulting
// build is broken in subtle ways (wrong runtime layout, missing types).
func TestRelaxWindowsBuildConstraints_RelaxesBitwidthFile(t *testing.T) {
	dir := t.TempDir()
	src := "//go:build (windows && amd64) || (windows && arm64)\n\npackage main\n\ntype X struct{}\n"
	path := filepath.Join(dir, "foo_windows_64.go")
	writeFile(t, path, src)

	if _, _, err := relaxWindowsBuildConstraints(dir, false, "amd64"); err != nil {
		t.Fatalf("relaxWindowsBuildConstraints: %v", err)
	}

	out := readFile(t, path)
	if !strings.Contains(out, "wasip1") {
		t.Errorf("bitwidth file build tag was not relaxed for wasip1:\n%s", out)
	}
}

// TestRelaxWindowsBuildConstraints_LeavesMismatchedBitwidthAlone asserts
// the bitwidth-pass is target-scoped: a 32-bit bitwidth file is NOT
// touched when targeting a 64-bit arch.
func TestRelaxWindowsBuildConstraints_LeavesMismatchedBitwidthAlone(t *testing.T) {
	dir := t.TempDir()
	src := "//go:build (windows && 386) || (windows && arm)\n\npackage main\n"
	path := filepath.Join(dir, "foo_windows_32.go")
	writeFile(t, path, src)

	if _, _, err := relaxWindowsBuildConstraints(dir, false, "amd64"); err != nil {
		t.Fatalf("relaxWindowsBuildConstraints: %v", err)
	}

	out := readFile(t, path)
	if strings.Contains(out, "wasip1") {
		t.Errorf("32-bit bitwidth file should NOT be relaxed when target is amd64:\n%s", out)
	}
}

// TestPatchMemmodForWASM_StubsHostOnlyFunctions asserts that the three
// host-only entry points (IAT hook, exception-table registration, TLS
// callbacks) are short-circuited with early returns. These operate on
// host-process memory that doesn't exist in WASM linear memory, so
// letting them execute faults the guest.
func TestPatchMemmodForWASM_StubsHostOnlyFunctions(t *testing.T) {
	dir, mainFile := setupMemmodFixture(t, memmodFixture)

	if err := patchMemmodForWASM(dir, false); err != nil {
		t.Fatalf("patchMemmodForWASM: %v", err)
	}

	out := readFile(t, mainFile)
	expectStubs := []string{
		"func hookRtlPcToFileHeader() error {\n\treturn nil",
		"func (module *Module) registerExceptionHandlers() {\n\treturn",
		"func (module *Module) executeTLS() {\n\treturn",
	}
	for _, want := range expectStubs {
		if !strings.Contains(out, want) {
			t.Errorf("expected stub not found:\n  %q\nnot present in:\n%s", want, out)
		}
	}
}

// TestPatchMemmodForWASM_BridgesRelocationThroughShadowHost asserts the
// performBaseRelocation path is rewritten to compute the relocation
// delta from the *host* base address (ShadowGetHostAddr), not the WASM
// linear-memory base. This is the actual fix for the regression — the
// DLL code executes in host shadow memory after VirtualAlloc, so
// using module.codeBase (a WASM address) for the delta produces
// nonsense pointers and the loaded DLL crashes on first call.
func TestPatchMemmodForWASM_BridgesRelocationThroughShadowHost(t *testing.T) {
	dir, mainFile := setupMemmodFixture(t, memmodFixture)

	if err := patchMemmodForWASM(dir, false); err != nil {
		t.Fatalf("patchMemmodForWASM: %v", err)
	}

	out := readFile(t, mainFile)
	if !strings.Contains(out, "windows.ShadowGetHostAddr(module.codeBase)") {
		t.Errorf("expected windows.ShadowGetHostAddr bridge in patched memmod, got:\n%s", out)
	}
	// The original WASM-broken expression must be gone.
	if strings.Contains(out, "locationDelta := module.headers.OptionalHeader.ImageBase - oldHeader.OptionalHeader.ImageBase\n\tif locationDelta != 0") {
		t.Errorf("unpatched relocation delta still present — host-base bridge not wired in")
	}
}

// TestPatchMemmodForWASM_BridgesDLLEntryThroughShadowCallEntry asserts
// the DLL entry point and detach calls go through ShadowCallEntry,
// which syncs WASM→Host memory, sets PAGE_EXECUTE_READWRITE, flushes
// the instruction cache, and calls at the correct host address. The
// original syscall.Syscall path passes a raw address as a proc handle,
// which the win32_syscalln dispatcher treats as an int32 handle ID
// and rejects.
func TestPatchMemmodForWASM_BridgesDLLEntryThroughShadowCallEntry(t *testing.T) {
	dir, mainFile := setupMemmodFixture(t, memmodFixture)

	if err := patchMemmodForWASM(dir, false); err != nil {
		t.Fatalf("patchMemmodForWASM: %v", err)
	}

	out := readFile(t, mainFile)
	// Attach path.
	if !strings.Contains(out, "windows.ShadowCallEntry(module.codeBase, module.headers.OptionalHeader.AddressOfEntryPoint, DLL_PROCESS_ATTACH)") {
		t.Errorf("expected ShadowCallEntry(..., DLL_PROCESS_ATTACH) in patched memmod, got:\n%s", out)
	}
	// Detach path.
	if !strings.Contains(out, "windows.ShadowCallEntry(module.codeBase, module.headers.OptionalHeader.AddressOfEntryPoint, DLL_PROCESS_DETACH)") {
		t.Errorf("expected ShadowCallEntry(..., DLL_PROCESS_DETACH) in patched memmod, got:\n%s", out)
	}
	// Original WASM-broken syscall.Syscall(module.entry,...) must be gone
	// from the attach call site.
	if strings.Contains(out, "syscall.Syscall(module.entry, 3, module.codeBase, uintptr(DLL_PROCESS_ATTACH), 0)") {
		t.Errorf("unpatched syscall.Syscall ATTACH call still present — entry-point bridge not wired in")
	}
}

// TestPatchMemmodForWASM_DoesNotInjectPE64Padding is the direct
// regression test for the original wrong fix: padPE64UptrFields would
// inject `_wfpad_<field> uint32` lines into IMAGE_OPTIONAL_HEADER,
// IMAGE_TLS_DIRECTORY, and IMAGE_LOAD_CONFIG_DIRECTORY under the false
// belief that GOARCH=wasm has uintptr=4. It actually has uintptr=8, so
// the padding makes the structs the WRONG size and corrupts every
// downstream offset. This test asserts no _wfpad_ marker appears in
// any memmod file after the full patch pipeline runs — catching any
// future re-wiring of padPE64UptrFields into the pipeline.
func TestPatchMemmodForWASM_DoesNotInjectPE64Padding(t *testing.T) {
	fixture := memmodFixture + "\n" + memmodPE64StructsFixture
	dir, _ := setupMemmodFixture(t, fixture)

	if err := patchMemmodForWASM(dir, false); err != nil {
		t.Fatalf("patchMemmodForWASM: %v", err)
	}

	memmodDir := filepath.Join(dir, "vendor", "github.com", "moloch--", "memmod")
	entries, err := os.ReadDir(memmodDir)
	if err != nil {
		t.Fatalf("read memmod dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		data := readFile(t, filepath.Join(memmodDir, e.Name()))
		if strings.Contains(data, "_wfpad_") {
			t.Errorf("file %s contains _wfpad_ marker — padPE64UptrFields appears to be wired back into the patch pipeline; this would corrupt PE64 struct layout on WASM (uintptr is 8 bytes, not 4)", e.Name())
		}
	}
}

// --- fixtures ---

// memmodFixture is a minimal memmod source that contains every literal
// string patchMemmodForWASM rewrites. The file MUST contain the
// `func (module *Module) buildImportTable()` marker for the patch
// function to pick it as the main file.
const memmodFixture = `package memmod

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

type Module struct {
	codeBase     uintptr
	entry        uintptr
	headers      *IMAGE_NT_HEADERS64
	isDLL        bool
	initialized  bool
	isRelocated  bool
}

func (module *Module) buildImportTable() error { return nil }

func (module *Module) performBaseRelocation(delta uintptr) (bool, error) { return true, nil }

func (module *Module) headerDirectory(idx int) *IMAGE_DATA_DIRECTORY { return nil }

func hookRtlPcToFileHeader() error {
	var kernelBase = uintptr(0)
	_ = kernelBase
	return nil
}

func (module *Module) registerExceptionHandlers() {
	directory := module.headerDirectory(0)
	_ = directory
}

func (module *Module) executeTLS() {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_TLS)
	_ = directory
}

func (module *Module) load(oldHeader *IMAGE_NT_HEADERS64) (err error) {
	// Adjust base address of imported data.
	locationDelta := module.headers.OptionalHeader.ImageBase - oldHeader.OptionalHeader.ImageBase
	if locationDelta != 0 {
		module.isRelocated, err = module.performBaseRelocation(locationDelta)
		if err != nil {
			return
		}
	}

	module.headers.OptionalHeader.ImageBase = module.codeBase

	if module.headers.OptionalHeader.AddressOfEntryPoint != 0 {
		module.entry = module.codeBase + uintptr(module.headers.OptionalHeader.AddressOfEntryPoint)
		if module.isDLL {
			// Notify library about attaching to process.
			r0, _, _ := syscall.Syscall(module.entry, 3, module.codeBase, uintptr(DLL_PROCESS_ATTACH), 0)
			successful := r0 != 0
			if !successful {
				err = windows.ERROR_DLL_INIT_FAILED
				return
			}
			module.initialized = true
		}
	}
	return nil
}

func (module *Module) Free() {
	if module.initialized {
		// Notify library about detaching from process.
		syscall.Syscall(module.entry, 3, module.codeBase, uintptr(DLL_PROCESS_DETACH), 0)
		module.initialized = false
	}
	_ = fmt.Sprintf
}

const (
	DLL_PROCESS_ATTACH        = 1
	DLL_PROCESS_DETACH        = 0
	IMAGE_DIRECTORY_ENTRY_TLS = 9
)

type IMAGE_DATA_DIRECTORY struct{}
type IMAGE_NT_HEADERS64 struct{ OptionalHeader IMAGE_OPTIONAL_HEADER }
`

// memmodPE64StructsFixture contains PE64 struct definitions identical
// to the ones padPE64UptrFields used to mangle. Appending this to the
// fixture lets TestPatchMemmodForWASM_DoesNotInjectPE64Padding detect
// any re-introduction of the padding hack.
const memmodPE64StructsFixture = `
type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	ImageBase                   uintptr
	AddressOfEntryPoint         uint32
	SizeOfStackReserve          uintptr
	SizeOfStackCommit           uintptr
	SizeOfHeapReserve           uintptr
	SizeOfHeapCommit            uintptr
}

type IMAGE_TLS_DIRECTORY struct {
	StartAddressOfRawData uintptr
	EndAddressOfRawData   uintptr
	AddressOfIndex        uintptr
	AddressOfCallBacks    uintptr
}
`

// setupMemmodFixture creates a temp dir with the memmod vendor layout
// patchMemmodForWASM expects, writes the given source to memmod.go,
// and returns (dir, mainFilePath).
func setupMemmodFixture(t *testing.T, src string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	memmodDir := filepath.Join(dir, "vendor", "github.com", "moloch--", "memmod")
	if err := os.MkdirAll(memmodDir, 0o755); err != nil {
		t.Fatalf("mkdir memmod fixture: %v", err)
	}
	main := filepath.Join(memmodDir, "memmod.go")
	writeFile(t, main, src)
	return dir, main
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
