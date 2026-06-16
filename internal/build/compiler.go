package build

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// sysshimModulePath is the Go module path of the vendored x/sys shim.
const sysshimModulePath = "golang.org/x/sys"

// contestedPair tracks a _wfwin.go file whose _wasip1.go stub was
// temporarily disabled to test if the real Windows code compiles for wasip1.
type contestedPair struct {
	wfwinPath  string // renamed foo_wfwin.go (currently tagged for wasip1)
	stubPath   string // original foo_wasip1.go location
	backupPath string // backup: foo_wasip1.go.wfstub
	pkgDir     string // package directory containing both files
}

// excludedFile tracks a Go source file that was excluded from wasip1 during
// build tag rewriting (e.g., a file whose negative build constraint like
// "!windows" was rewritten to "!windows && !wasip1", excluding it from wasip1).
type excludedFile struct {
	path   string // full path to the excluded file
	pkgDir string // package directory containing the file
	data   []byte // optional: file content (for files removed during processing)
}

// CompileWASM compiles a Go package to WASM using the patched GOROOT.
// Returns the path to the compiled .wasm file.
//
// If the guest package depends on golang.org/x/sys, wasmforge automatically
// injects a replace directive pointing to the vendored sysshim so that
// import "golang.org/x/sys/windows" compiles for wasip1.
func CompileWASM(patchedGOROOT, pkg, tmpDir string, verbose, win32APIs bool, targetGOOS, targetGOARCH, buildTags string) (string, error) {
	wasmOut := filepath.Join(tmpDir, "app.wasm")

	// Resolve the package path. If it's a directory, find the enclosing
	// module root (the directory containing go.mod) and build the relative
	// package path from there.
	buildPkg := pkg
	var workDir string

	absPath, err := filepath.Abs(pkg)
	if err == nil {
		if info, err := os.Stat(absPath); err == nil && info.IsDir() {
			modRoot := findGoModRoot(absPath)
			if modRoot != "" && modRoot != absPath {
				// Package is a subdirectory of the module root.
				// Use the module root as workDir and compute the
				// relative package path.
				rel, err := filepath.Rel(modRoot, absPath)
				if err == nil {
					workDir = modRoot
					buildPkg = "./" + filepath.ToSlash(rel)
				} else {
					workDir = absPath
					buildPkg = "."
				}
			} else {
				workDir = absPath
				buildPkg = "."
			}
		}
	}

	// If the guest module depends on golang.org/x/sys, inject the sysshim
	// replace directive so wasip1 builds can use golang.org/x/sys/windows.
	originalWorkDir := workDir
	if workDir != "" {
		injected, err := injectSysshimReplace(workDir, tmpDir, verbose, win32APIs)
		if err != nil {
			return "", fmt.Errorf("injecting sysshim replace: %w", err)
		}
		if injected != "" {
			workDir = injected
		}
	}

	// If the guest module depends on github.com/ebitengine/purego, inject
	// the purego sysshim replace directive so wasip1 builds can use purego.
	if workDir != "" {
		injected, err := injectPuregoSysshimReplace(workDir, tmpDir, verbose)
		if err != nil {
			return "", fmt.Errorf("injecting purego sysshim replace: %w", err)
		}
		if injected != "" {
			workDir = injected
		}
	}

	// Rewrite runtime.GOOS/runtime.GOARCH in guest source so the WASM guest
	// reports the target platform instead of wasip1/wasm. If we don't already
	// have a shadow copy (sysshim injection wasn't needed), create one now so
	// we never mutate the user's original source files.
	if workDir != "" && (targetGOOS != "wasip1" || targetGOARCH != "wasm") {
		if workDir == originalWorkDir {
			shadowDir := filepath.Join(tmpDir, "platform-guest")
			if err := copyDir(workDir, shadowDir); err != nil {
				return "", fmt.Errorf("creating shadow copy for platform rewriting: %w", err)
			}
			workDir = shadowDir
			if verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: created shadow copy for platform rewriting\n")
			}
		}
		if err := rewritePlatformConstants(workDir, targetGOOS, targetGOARCH, verbose); err != nil {
			return "", fmt.Errorf("rewriting platform constants: %w", err)
		}
		if err := patchGuestWazeroCompiler(workDir, verbose); err != nil {
			return "", fmt.Errorf("patching guest wazero compiler detection: %w", err)
		}
	}

	// Inject wasip1 overrides for unsafe host pointer dereference patterns.
	// Guests that use unsafe.Slice on host pointers (common in transport
	// helpers around purego/ObjC) trap in WASM. Replace with
	// darwin.ReadHostMemory-based versions.
	if workDir != "" && workDir != originalWorkDir && targetGOOS == "darwin" {
		if n, err := injectUnsafeHelperOverrides(workDir, verbose); err != nil && verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: unsafe helper override warning: %v\n", err)
		} else if n > 0 && verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: injected %d unsafe helper override(s)\n", n)
		}
	}

	// Use the go binary from the patched GOROOT directly.
	// This is critical: the system 'go' binary may be a wrapper (e.g., go 1.22)
	// that delegates to a toolchain from the module cache, which would ignore
	// our patched GOROOT. Using the binary directly avoids this.
	goBin := filepath.Join(patchedGOROOT, "bin", "go")
	buildEnv := append(os.Environ(),
		"GOOS=wasip1",
		"GOARCH=wasm",
		"GOROOT="+patchedGOROOT,
		"GOWORK=off",
		"GOTOOLCHAIN=local",
	)

	// When Win32 APIs are enabled, relax _windows.go build constraints so
	// the guest source files compile for wasip1. The sysshim provides
	// wasip1-compatible implementations of golang.org/x/sys/windows, so
	// Windows-targeted Go code can compile once the filename-based GOOS
	// constraint is removed.
	var contested []contestedPair
	var excluded []excludedFile
	if win32APIs && workDir != "" {
		contested, excluded, err = relaxWindowsBuildConstraints(workDir, verbose)
		if err != nil {
			return "", fmt.Errorf("relaxing build constraints: %w", err)
		}
	}

	// Fix module cache dependencies that have _windows.go implementations
	// alongside fallback files containing panic("Not implemented"). These
	// fallbacks compile fine for wasip1 but panic at runtime.
	//
	// With --win32-apis: copy the module, apply build constraint relaxation
	// so the Windows implementation is used (it will compile with sysshim).
	// Without --win32-apis: copy the module, replace panic() with no-op
	// return (the Windows impl uses DLL loading which won't compile).
	//
	// Only run on shadow copies — this mutates go.mod with replace directives.
	if workDir != "" && workDir != originalWorkDir {
		if err := fixModCachePanicFallbacks(workDir, goBin, buildEnv, tmpDir, win32APIs, verbose); err != nil && verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: modcache panic fallback fix warning: %v\n", err)
		}
	}

	runBuild := func() ([]byte, error) {
		args := []string{"build", "-a"}
		if buildTags != "" {
			args = append(args, "-tags", buildTags)
		}
		args = append(args, "-o", wasmOut, buildPkg)
		cmd := exec.Command(goBin, args...)
		cmd.Env = buildEnv
		if workDir != "" {
			cmd.Dir = workDir
		}
		var stderrBuf bytes.Buffer
		if verbose {
			cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)
			cmd.Stdout = os.Stdout
		} else {
			cmd.Stderr = &stderrBuf
		}
		err := cmd.Run()
		return stderrBuf.Bytes(), err
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: compiling %s to WASM\n", pkg)
		fmt.Fprintf(os.Stderr, "wasmforge: GOROOT=%s\n", patchedGOROOT)
	}

	stderrData, buildErr := runBuild()

	// If build failed, try generating auto-stubs for symbols lost when files
	// were excluded from wasip1 during build tag rewriting. Accumulate stderr
	// across iterations so regenerated stubs include symbols from ALL attempts.
	var accumulatedStderr []byte
	for attempt := 0; attempt < 3 && buildErr != nil && len(excluded) > 0; attempt++ {
		accumulatedStderr = append(accumulatedStderr, stderrData...)
		generated, genErr := generateAutoStubs(accumulatedStderr, excluded, workDir, tmpDir, verbose)
		if genErr != nil && verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: auto-stub generation warning: %v\n", genErr)
		}
		if generated == 0 {
			break
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: generated %d auto-stub(s), retrying build (attempt %d)\n", generated, attempt+1)
		}
		stderrData, buildErr = runBuild()
	}

	// If build failed and we have contested stubs, try restoring needed ones.
	if buildErr != nil && len(contested) > 0 {
		restored := restoreNeededStubs(stderrData, contested, workDir, verbose)
		if restored > 0 {
			if verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: retrying build with %d stub(s) restored\n", restored)
			}
			stderrData, buildErr = runBuild()
		}
	}

	// Clean up any remaining .wfstub backup files.
	cleanupStubBackups(contested)

	if buildErr != nil {
		return "", fmt.Errorf("WASM compilation failed: %w", buildErr)
	}

	if verbose {
		info, _ := os.Stat(wasmOut)
		if info != nil {
			fmt.Fprintf(os.Stderr, "wasmforge: compiled WASM: %s (%d bytes)\n", wasmOut, info.Size())
		}
	}

	return wasmOut, nil
}

// sysshimSourceBase returns a directory B such that filepath.Join(B,
// "sysshim", <pkg>) is a valid wasmforge sysshim package source tree.
// In development mode (wasmforge module source on disk), B is
// <moduleRoot>/internal. In distribution mode (standalone binary), B is
// the cached temp directory populated from the embedded build_assets
// bundle, where the sysshim tree was packed under the "sysshim/" prefix.
func sysshimSourceBase() (string, error) {
	if root := findModuleRoot(); root != "" {
		return filepath.Join(root, "internal"), nil
	}
	return ensureAssetsExtracted()
}

// injectSysshimReplace checks whether the guest module at pkgDir depends on
// golang.org/x/sys. If it does, it creates a temporary copy of the module
// directory with the sysshim replacing the original x/sys code. For vendored
// modules, the vendored x/sys directory and modules.txt are patched directly.
// For non-vendored modules, a replace directive is added to go.mod.
// Returns the new workDir path, or "" if no injection was necessary.
func injectSysshimReplace(pkgDir, tmpDir string, verbose, win32APIs bool) (string, error) {
	gomodPath := filepath.Join(pkgDir, "go.mod")
	data, err := os.ReadFile(gomodPath)
	if err != nil {
		// No go.mod found; nothing to inject.
		return "", nil
	}

	content := string(data)
	if !strings.Contains(content, sysshimModulePath) {
		// Module does not depend on golang.org/x/sys; no injection needed.
		return "", nil
	}

	// Locate the sysshim directory (relative to the wasmforge module root, or
	// from the embedded build assets when running as a standalone binary).
	base, sysErr := sysshimSourceBase()
	if sysErr != nil {
		if win32APIs {
			return "", fmt.Errorf("locating wasmforge sysshim source: %w", sysErr)
		}
		return "", nil
	}
	sysshimDir := filepath.Join(base, "sysshim")
	if _, err := os.Stat(sysshimDir); err != nil {
		if win32APIs {
			return "", fmt.Errorf("sysshim directory not found at %s", sysshimDir)
		}
		return "", nil
	}

	// Check that the go.mod doesn't already have a replace for golang.org/x/sys.
	if strings.Contains(content, "replace "+sysshimModulePath) {
		return "", nil
	}

	// Create a shadow module directory in tmpDir.
	shadowDir := filepath.Join(tmpDir, "sysshim-guest")
	if err := copyDir(pkgDir, shadowDir); err != nil {
		return "", fmt.Errorf("copying guest module: %w", err)
	}

	// Check if the module uses vendored dependencies.
	vendorDir := filepath.Join(shadowDir, "vendor")
	vendorModulesTxt := filepath.Join(vendorDir, "modules.txt")
	if _, err := os.Stat(vendorModulesTxt); err == nil {
		// Vendored module: replace the vendored x/sys content and update modules.txt.
		if err := injectSysshimVendored(shadowDir, sysshimDir, verbose); err != nil {
			return "", fmt.Errorf("injecting sysshim into vendor: %w", err)
		}
	} else {
		// Non-vendored: append replace directive to go.mod.
		shadowGomod := filepath.Join(shadowDir, "go.mod")
		shadowData, err := os.ReadFile(shadowGomod)
		if err != nil {
			return "", fmt.Errorf("reading shadow go.mod: %w", err)
		}
		shadowContent := strings.TrimRight(string(shadowData), "\n") + "\n" +
			"replace " + sysshimModulePath + " => " + sysshimDir + "\n"
		if err := os.WriteFile(shadowGomod, []byte(shadowContent), 0o644); err != nil {
			return "", fmt.Errorf("writing shadow go.mod: %w", err)
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: injected sysshim replace: %s => %s\n",
			sysshimModulePath, sysshimDir)
	}

	return shadowDir, nil
}

// injectSysshimVendored replaces the vendored golang.org/x/sys directory with
// the wasmforge sysshim and updates vendor/modules.txt to reflect the change.
// This handles Go projects that use `go mod vendor` for dependency management.
func injectSysshimVendored(shadowDir, sysshimDir string, verbose bool) error {
	vendorDir := filepath.Join(shadowDir, "vendor")
	vendorSysDir := filepath.Join(vendorDir, "golang.org", "x", "sys")

	// Remove the existing vendored x/sys.
	if err := os.RemoveAll(vendorSysDir); err != nil {
		return fmt.Errorf("removing vendored x/sys: %w", err)
	}

	// Copy the sysshim content into the vendor location.
	// The sysshim has structure: go.mod, windows/
	// We need to copy the windows/ subdirectory and any other content.
	if err := copyDir(sysshimDir, vendorSysDir); err != nil {
		return fmt.Errorf("copying sysshim to vendor: %w", err)
	}

	// Remove go.mod from vendored copy (vendor directories don't contain go.mod).
	os.Remove(filepath.Join(vendorSysDir, "go.mod"))
	os.Remove(filepath.Join(vendorSysDir, "go.sum"))

	// Update vendor/modules.txt to list the sysshim's packages instead of
	// the original x/sys packages. Walk the sysshim directory to discover
	// the actual packages provided.
	sysshimPkgs := []string{}
	err := filepath.Walk(vendorSysDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return err
		}
		// Check if this directory contains .go files.
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil
		}
		hasGo := false
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
				hasGo = true
				break
			}
		}
		if hasGo {
			rel, err := filepath.Rel(vendorDir, path)
			if err != nil {
				return nil
			}
			sysshimPkgs = append(sysshimPkgs, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walking sysshim vendor dir: %w", err)
	}

	// Rewrite vendor/modules.txt: replace the x/sys section.
	modulesTxtPath := filepath.Join(vendorDir, "modules.txt")
	modulesTxtData, err := os.ReadFile(modulesTxtPath)
	if err != nil {
		return fmt.Errorf("reading modules.txt: %w", err)
	}

	lines := strings.Split(string(modulesTxtData), "\n")
	var newLines []string
	inSysSection := false
	sysHeaderWritten := false
	for _, line := range lines {
		if strings.HasPrefix(line, "# golang.org/x/sys ") {
			// Start of x/sys section — replace package list but keep the
			// original version header so it matches go.mod's require line.
			inSysSection = true
			if !sysHeaderWritten {
				newLines = append(newLines, line) // Keep original "# golang.org/x/sys vX.Y.Z"
				sysHeaderWritten = true
			}
			continue
		}
		if inSysSection {
			if strings.HasPrefix(line, "## explicit") {
				// Replace the Go version with sysshim's minimum (go 1.21)
				// to avoid language version errors (e.g. unsafe.SliceData).
				explicitLine := "## explicit; go 1.21"
				newLines = append(newLines, explicitLine)
				for _, pkg := range sysshimPkgs {
					newLines = append(newLines, pkg)
				}
				continue
			}
			// Skip original package lines until we hit the next module header or end.
			if strings.HasPrefix(line, "# ") || line == "" {
				inSysSection = false
				newLines = append(newLines, line)
			}
			continue
		}
		newLines = append(newLines, line)
	}

	if err := os.WriteFile(modulesTxtPath, []byte(strings.Join(newLines, "\n")), 0o644); err != nil {
		return fmt.Errorf("writing modules.txt: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: replaced vendored x/sys with sysshim (%d packages)\n", len(sysshimPkgs))
	}

	return nil
}

// injectUnsafeHelperOverrides walks the shadow copy looking for Go files that
// use unsafe.Slice to dereference host pointers (a common pattern in transport
// helpers built around purego/ObjC). For each match, it injects a _wasip1.go
// override that uses darwin.ReadHostMemory instead.
func injectUnsafeHelperOverrides(workDir string, verbose bool) (int, error) {
	count := 0
	err := filepath.Walk(workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(info.Name(), ".go") {
			return nil
		}
		if strings.HasSuffix(info.Name(), "_wasip1.go") || strings.HasSuffix(info.Name(), "_wasm.go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)

		// Detect the pattern: file contains unsafe.Slice AND a function like
		// byteSliceFromPtr or similar host pointer dereference helpers.
		if !strings.Contains(content, "unsafe.Slice") {
			return nil
		}
		if !strings.Contains(content, "byteSliceFromPtr") && !strings.Contains(content, "ByteSliceFromPtr") {
			return nil
		}

		// Extract the package name from the file.
		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, data, parser.PackageClauseOnly)
		if parseErr != nil || f == nil {
			return nil
		}
		pkgName := f.Name.Name

		// Generate the override file in the same directory.
		dir := filepath.Dir(path)
		overridePath := filepath.Join(dir, "unsafe_helpers_wasip1.go")
		if _, err := os.Stat(overridePath); err == nil {
			return nil // already exists
		}

		override := fmt.Sprintf(`//go:build wasip1

package %s

import (
	"encoding/binary"

	"github.com/praetorian-inc/wasmforge/guest/darwin"
)

// byteSliceFromPtr reads bytes from a host memory address into a new slice.
// In WASM, host pointers are outside linear memory so unsafe.Slice would trap.
func byteSliceFromPtr(ptr uintptr, length int) []byte {
	if ptr == 0 || length <= 0 {
		return nil
	}
	buf := make([]byte, length)
	_ = darwin.ReadHostMemory(ptr, 0, buf)
	return buf
}

// readByteAtOffset reads a single byte from a host memory address at offset.
func readByteAtOffset(base uintptr, offset int) byte {
	var b [1]byte
	_ = darwin.ReadHostMemory(base, uint32(offset), b[:])
	return b[0]
}

// readUintptrAtOffset reads a uintptr from a host memory address at offset.
func readUintptrAtOffset(base uintptr, offset int) uintptr {
	var b [8]byte
	_ = darwin.ReadHostMemory(base, uint32(offset), b[:])
	return uintptr(binary.LittleEndian.Uint64(b[:]))
}
`, pkgName)

		if err := os.WriteFile(overridePath, []byte(override), 0o644); err != nil {
			return nil
		}

		// Disable the original file for wasip1 by prepending a build constraint.
		if !strings.Contains(content, "//go:build") {
			newContent := "//go:build !wasip1\n\n" + content
			_ = os.WriteFile(path, []byte(newContent), 0o644)
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: injected unsafe helper override: %s\n", overridePath)
		}
		count++
		return nil
	})
	return count, err
}

// puregoSysshimModulePath is the Go module path for the purego sysshim.
const puregoSysshimModulePath = "github.com/ebitengine/purego"

// injectPuregoSysshimReplace checks whether the guest module at pkgDir depends
// on github.com/ebitengine/purego. If it does, it injects a replace directive
// (or replaces the vendored copy) pointing to WasmForge's purego sysshim.
// Returns the new workDir path, or "" if no injection was necessary.
func injectPuregoSysshimReplace(pkgDir, tmpDir string, verbose bool) (string, error) {
	gomodPath := filepath.Join(pkgDir, "go.mod")
	data, err := os.ReadFile(gomodPath)
	if err != nil {
		return "", nil
	}

	content := string(data)
	if !strings.Contains(content, puregoSysshimModulePath) {
		return "", nil
	}

	// Already has a replace? Skip.
	if strings.Contains(content, "replace "+puregoSysshimModulePath) {
		return "", nil
	}

	base, sysErr := sysshimSourceBase()
	if sysErr != nil {
		return "", fmt.Errorf("locating wasmforge purego sysshim source: %w", sysErr)
	}
	puregoSysshimDir := filepath.Join(base, "sysshim", "purego")
	if _, err := os.Stat(puregoSysshimDir); err != nil {
		return "", fmt.Errorf("purego sysshim directory not found at %s", puregoSysshimDir)
	}

	// Create shadow copy if we're still on the original.
	shadowDir := pkgDir
	if pkgDir == filepath.Join(tmpDir, "sysshim-guest") || pkgDir == filepath.Join(tmpDir, "platform-guest") || pkgDir == filepath.Join(tmpDir, "purego-guest") {
		// Already a shadow copy from a prior injection — reuse it.
		shadowDir = pkgDir
	} else {
		shadowDir = filepath.Join(tmpDir, "purego-guest")
		if err := copyDir(pkgDir, shadowDir); err != nil {
			return "", fmt.Errorf("copying guest module for purego sysshim: %w", err)
		}
	}

	// Check for vendored dependencies.
	vendorDir := filepath.Join(shadowDir, "vendor")
	vendorModulesTxt := filepath.Join(vendorDir, "modules.txt")
	if _, err := os.Stat(vendorModulesTxt); err == nil {
		if err := injectPuregoSysshimVendored(shadowDir, puregoSysshimDir, verbose); err != nil {
			return "", fmt.Errorf("injecting purego sysshim into vendor: %w", err)
		}
	} else {
		// Non-vendored: append replace directive to go.mod.
		shadowGomod := filepath.Join(shadowDir, "go.mod")
		shadowData, err := os.ReadFile(shadowGomod)
		if err != nil {
			return "", fmt.Errorf("reading shadow go.mod: %w", err)
		}
		// The purego sysshim transitively depends on wasmforge (for guest/darwin).
		// Add both the purego replace AND wasmforge require+replace.
		wasmforgeModRoot := filepath.Dir(filepath.Dir(puregoSysshimDir)) // internal/sysshim/purego -> wasmforge root
		wasmforgeModRoot = filepath.Dir(wasmforgeModRoot)                // internal/sysshim -> internal -> wasmforge
		shadowContent := strings.TrimRight(string(shadowData), "\n") + "\n" +
			"require github.com/praetorian-inc/wasmforge v0.0.0\n" +
			"replace " + puregoSysshimModulePath + " => " + puregoSysshimDir + "\n" +
			"replace github.com/praetorian-inc/wasmforge => " + wasmforgeModRoot + "\n"
		if err := os.WriteFile(shadowGomod, []byte(shadowContent), 0o644); err != nil {
			return "", fmt.Errorf("writing shadow go.mod: %w", err)
		}
	}

	// Run go mod tidy on the shadow copy to resolve transitive deps from
	// the purego sysshim (which requires wasmforge → wazero, x/sys, etc.).
	tidyCmd := exec.Command("go", "mod", "tidy")
	tidyCmd.Dir = shadowDir
	tidyCmd.Env = append(os.Environ(), "GOWORK=off")
	if tidyOut, err := tidyCmd.CombinedOutput(); err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: go mod tidy warning: %s\n", string(tidyOut))
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: injected purego sysshim replace: %s => %s\n",
			puregoSysshimModulePath, puregoSysshimDir)
	}

	return shadowDir, nil
}

// injectPuregoSysshimVendored replaces the vendored purego directory with the
// wasmforge purego sysshim and updates vendor/modules.txt.
func injectPuregoSysshimVendored(shadowDir, puregoSysshimDir string, verbose bool) error {
	vendorDir := filepath.Join(shadowDir, "vendor")
	vendorPuregoDir := filepath.Join(vendorDir, "github.com", "ebitengine", "purego")

	if err := os.RemoveAll(vendorPuregoDir); err != nil {
		return fmt.Errorf("removing vendored purego: %w", err)
	}

	if err := copyDir(puregoSysshimDir, vendorPuregoDir); err != nil {
		return fmt.Errorf("copying purego sysshim to vendor: %w", err)
	}

	// Remove go.mod/go.sum from vendored copy.
	os.Remove(filepath.Join(vendorPuregoDir, "go.mod"))
	os.Remove(filepath.Join(vendorPuregoDir, "go.sum"))

	// Walk the sysshim to discover packages provided.
	sysshimPkgs := []string{}
	err := filepath.Walk(vendorPuregoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return err
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil
		}
		hasGo := false
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
				hasGo = true
				break
			}
		}
		if hasGo {
			rel, err := filepath.Rel(vendorDir, path)
			if err != nil {
				return nil
			}
			sysshimPkgs = append(sysshimPkgs, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walking purego sysshim vendor dir: %w", err)
	}

	// Rewrite vendor/modules.txt: replace the purego section.
	modulesTxtPath := filepath.Join(vendorDir, "modules.txt")
	modulesTxtData, err := os.ReadFile(modulesTxtPath)
	if err != nil {
		return fmt.Errorf("reading modules.txt: %w", err)
	}

	lines := strings.Split(string(modulesTxtData), "\n")
	var newLines []string
	inPuregoSection := false
	puregoHeaderWritten := false
	for _, line := range lines {
		if strings.HasPrefix(line, "# github.com/ebitengine/purego ") {
			inPuregoSection = true
			if !puregoHeaderWritten {
				newLines = append(newLines, line)
				puregoHeaderWritten = true
			}
			continue
		}
		if inPuregoSection {
			if strings.HasPrefix(line, "## explicit") {
				newLines = append(newLines, "## explicit; go 1.18")
				for _, pkg := range sysshimPkgs {
					newLines = append(newLines, pkg)
				}
				continue
			}
			if strings.HasPrefix(line, "# ") || line == "" {
				inPuregoSection = false
				newLines = append(newLines, line)
			}
			continue
		}
		newLines = append(newLines, line)
	}

	if err := os.WriteFile(modulesTxtPath, []byte(strings.Join(newLines, "\n")), 0o644); err != nil {
		return fmt.Errorf("writing modules.txt: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: replaced vendored purego with sysshim (%d packages)\n", len(sysshimPkgs))
	}

	return nil
}

// relaxWindowsBuildConstraints renames _windows.go files in the shadow copy to
// remove the implicit GOOS=windows build constraint from the filename. This
// allows them to compile when GOOS=wasip1, since wasmforge's sysshim provides
// wasip1-compatible implementations of the Windows APIs they depend on.
//
// Files named foo_windows.go become foo_wfwin.go (doesn't match any GOOS).
// Files named foo_windows_amd64.go become foo_wfwin.go (removes GOARCH too,
// since the WASM target is GOARCH=wasm).
//
// Additionally, header-based build tags are rewritten:
//   - "//go:build ... windows ..." gets "|| wasip1" added so the file compiles
//   - "//go:build !windows" or "!darwin && !windows && !linux" files that would
//     conflict with an enabled _windows.go counterpart are disabled
func relaxWindowsBuildConstraints(dir string, verbose bool) ([]contestedPair, []excludedFile, error) {
	count := 0
	rewrittenCount := 0
	var contested []contestedPair
	var excluded []excludedFile

	// Compute vendor paths to skip during rewriting.
	// The sysshim already has correct wasip1 build tags and must not be
	// rewritten (doing so would cause redeclaration errors between
	// e.g. memory.go and memory_wasip1.go).
	sysshimVendorDir := filepath.Join(dir, "vendor", "golang.org", "x", "sys")

	// Vendor packages that use deep Windows kernel APIs (Winsock,
	// named pipes, NT internals) which cannot work through our sysshim.
	// These must stay windows-only to avoid type mismatches (e.g.,
	// syscall.Socket returns int on wasip1 but Handle on Windows).
	skipVendorDirs := []string{
		filepath.Join(dir, "vendor", "github.com", "lesnuages", "go-winio"),
		filepath.Join(dir, "vendor", "github.com", "Microsoft", "go-winio"),
		// wazero's internal/sysfs and sys windows ports use
		// syscall.SetFileTime / NsecToFiletime / GENERIC_READ /
		// Win32FileAttributeData etc that don't exist in wasip1's syscall
		// package. Guests embedding wazero (e.g. nested WASM runtimes —
		// testdata/nested_wasm*) get the *_unsupported.go path instead,
		// which compiles cleanly on wasip1. Two paths cover both the
		// vendor layout and the direct (replace-directive) layout that
		// wasmforge uses for its own fork.
		filepath.Join(dir, "vendor", "github.com", "tetratelabs", "wazero", "internal", "sysfs"),
		filepath.Join(dir, "vendor", "github.com", "tetratelabs", "wazero", "sys"),
		filepath.Join(dir, "wazero", "internal", "sysfs"),
		filepath.Join(dir, "wazero", "sys"),
	}
	shouldSkipDir := func(path string) bool {
		for _, skip := range skipVendorDirs {
			if strings.HasPrefix(path, skip) {
				return true
			}
		}
		return false
	}

	// Derive module paths from vendor dirs so we can detect files that
	// import skipped packages (e.g., "github.com/Microsoft/go-winio").
	vendorPrefix := filepath.Join(dir, "vendor") + string(filepath.Separator)
	var skipModulePaths []string
	for _, vd := range skipVendorDirs {
		mp := strings.TrimPrefix(vd, vendorPrefix)
		mp = filepath.ToSlash(mp)
		skipModulePaths = append(skipModulePaths, mp)
	}

	// First pass: rewrite //go:build header tags.
	// - Files with "windows" in a positive constraint get "|| wasip1" added.
	// - Files with "!windows" that have a _windows.go counterpart get disabled.
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip the vendored sysshim directory entirely.
			if path == sysshimVendorDir {
				return filepath.SkipDir
			}
			// Skip vendor packages with deep Windows kernel dependencies.
			if shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Skip _windows.go files (handled in second pass).
		base := filepath.Base(path)
		name := strings.TrimSuffix(base, ".go")
		if hasWindowsSuffix(name) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		newData, changed := rewriteWindowsBuildTags(data)
		if changed {
			// Check if this file is being EXCLUDED from wasip1 (negative
			// constraint like "!windows && !wasip1"). These files lose their
			// symbols for wasip1 builds and may need auto-generated stubs.
			if fileExcludesWasip1FromData(newData) {
				excluded = append(excluded, excludedFile{
					path:   path,
					pkgDir: filepath.Dir(path),
				})
			}
			// Transform syscall.Close → syscall.CloseW for Windows code
			// (wasip1's Close takes int, not Handle).
			newData = rewriteSyscallTypeMismatches(newData)
			if err := os.WriteFile(path, newData, info.Mode()); err != nil {
				return fmt.Errorf("rewriting build tags in %s: %w", path, err)
			}
			rewrittenCount++
		} else {
			// File was not rewritten. If it has arch-specific windows
			// constraints (e.g., "(windows && amd64)"), it was skipped by
			// containsArch() and won't compile for wasip1/wasm. Track it
			// as excluded so auto-stubs can provide its symbols.
			if fileHasArchConstraintNoWasm(data) {
				excluded = append(excluded, excludedFile{
					path:   path,
					pkgDir: filepath.Dir(path),
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// Second pass: rename _windows.go files.
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip the vendored sysshim directory entirely.
			if path == sysshimVendorDir {
				return filepath.SkipDir
			}
			// Skip vendor packages with deep Windows kernel dependencies.
			if shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		base := filepath.Base(path)
		name := strings.TrimSuffix(base, ".go")
		if !hasWindowsSuffix(name) {
			return nil
		}

		newName := removeWindowsSuffix(name) + ".go"
		newPath := filepath.Join(filepath.Dir(path), newName)
		keepWasip1Stub := false
		var replacedData []byte // content of replaced fallback file (for panic rewriting)

		// If the target name already exists, check if it's a non-windows
		// stub that was rewritten to exclude wasip1. In that case, the
		// _windows.go file is the correct implementation for wasip1 and
		// should replace it.
		if _, err := os.Stat(newPath); err == nil {
			if fileExcludesWasip1(newPath) {
				// The existing file excludes wasip1 (it's a non-windows
				// stub). Remove it so the _windows.go content takes its
				// place. Track it as excluded so auto-stubs can use its
				// declarations if the replacement doesn't compile.
				// Read the content before removing — auto-stub will need it.
				replacedData, _ = os.ReadFile(newPath)
				excluded = append(excluded, excludedFile{
					path:   newPath,
					pkgDir: filepath.Dir(newPath),
					data:   replacedData,
				})
				if verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: replacing %s with %s (stub excludes wasip1)\n", newName, base)
				}
				if err := os.Remove(newPath); err != nil {
					return fmt.Errorf("removing conflicting %s: %w", newName, err)
				}
			} else {
				// The existing file does not exclude wasip1 — it likely
				// contains shared types/interfaces that coexist with the
				// Windows-specific code. Use a non-colliding name so both
				// files compile together.
				stem := removeWindowsSuffix(name)
				newName = stem + "_wfwin.go"
				newPath = filepath.Join(filepath.Dir(path), newName)
				if verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: renaming %s → %s (collision with %s)\n", base, newName, stem+".go")
				}
				// Check if a _wasip1.go stub exists. Optimistically
				// disable the stub and try compiling the real code.
				// If it fails, the stub will be restored before retry.
				wasip1Stub := filepath.Join(filepath.Dir(path), stem+"_wasip1.go")
				if _, err := os.Stat(wasip1Stub); err == nil {
					backupPath := wasip1Stub + ".wfstub"
					if err := os.Rename(wasip1Stub, backupPath); err != nil {
						// Can't back up — fall back to conservative behavior.
						keepWasip1Stub = true
						if verbose {
							fmt.Fprintf(os.Stderr, "wasmforge: keeping %s (backup failed: %v)\n", stem+"_wasip1.go", err)
						}
					} else {
						contested = append(contested, contestedPair{
							wfwinPath:  newPath,
							stubPath:   wasip1Stub,
							backupPath: backupPath,
							pkgDir:     filepath.Dir(path),
						})
						if verbose {
							fmt.Fprintf(os.Stderr, "wasmforge: trying %s for wasip1 (stub backed up)\n", newName)
						}
					}
				}
			}
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		// Transform syscall type mismatches for Windows code
		// (wasip1's Close/Read/Write/Seek take int, not Handle).
		data = rewriteSyscallTypeMismatches(data)

		// If the Windows file still has type mismatches we can't fix
		// (e.g., syscall.Handle in unsupported contexts, syscall.MustLoadDLL
		// in init), and we replaced a fallback file, restore the fallback
		// with panic bodies converted to zero-value returns.
		if replacedData != nil && hasRemainingHandleMismatches(data) {
			fallbackData, rewrote := rewritePanicFallbacks(replacedData)
			if rewrote {
				fallbackData = forceBuildTag(fallbackData, "wasip1")
				if err := os.WriteFile(newPath, fallbackData, 0o644); err != nil {
					return fmt.Errorf("restoring fallback %s: %w", newName, err)
				}
				// Force Windows file to windows-only with a _wfwin.go name.
				data = forceBuildTag(data, "windows")
				wfwinName := removeWindowsSuffix(name) + "_wfwin.go"
				wfwinPath := filepath.Join(filepath.Dir(path), wfwinName)
				if err := os.WriteFile(wfwinPath, data, info.Mode()); err != nil {
					return fmt.Errorf("writing %s: %w", wfwinName, err)
				}
				if err := os.Remove(path); err != nil {
					return fmt.Errorf("removing %s: %w", path, err)
				}
				if verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: restored fallback for %s (panic→zero, windows content → %s)\n", newName, wfwinName)
				}
				count++
				return nil
			}
		}

		// If this file imports a skipped vendor package, it cannot
		// compile for wasip1 — force windows-only and track as excluded
		// so auto-stubs can provide its symbols if needed.
		if fileImportsSkippedModule(data, skipModulePaths) {
			keepWasip1Stub = true
			excluded = append(excluded, excludedFile{
				path:   path,
				pkgDir: filepath.Dir(path),
				data:   data,
			})
			if verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: %s imports skipped package, forcing windows-only\n", base)
			}
		}

		if keepWasip1Stub {
			// A _wasip1.go stub provides the implementation for wasip1.
			// Constrain this _wfwin.go file to windows-only so it doesn't
			// conflict with the stub.
			data, _ = rewriteWindowsBuildTags(data)
			// Override: force windows-only regardless of what tags were present.
			data = forceBuildTag(data, "windows")
		} else {
			// Rewrite build tags to include wasip1 so the Windows code
			// also compiles for WASM.
			var tagChanged bool
			data, tagChanged = rewriteWindowsBuildTags(data)
			if !tagChanged {
				// Tags were NOT rewritten. This means either:
				// (a) the file had no build tags (relied on _windows suffix), or
				// (b) the file has arch-specific constraints that don't
				//     contain "windows" (e.g., "386 || amd64 || arm64")
				//     which containsArch() skipped.
				//
				// For case (b), the file won't compile for wasip1/wasm
				// since GOARCH=wasm doesn't match arch constraints. Track
				// it as excluded so auto-stubs can provide its symbols.
				if fileHasArchConstraintNoWasm(data) {
					excluded = append(excluded, excludedFile{
						path:   path,
						pkgDir: filepath.Dir(path),
						data:   data,
					})
				}
				// For _wfwin.go renames that had no tags, inject a tag.
				if strings.HasSuffix(newName, "_wfwin.go") {
					data = injectBuildTag(data, "windows || wasip1")
				}
			}
		}

		if err := os.WriteFile(newPath, data, info.Mode()); err != nil {
			return fmt.Errorf("writing %s: %w", newPath, err)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("removing %s: %w", path, err)
		}
		count++
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if verbose {
		if count > 0 {
			fmt.Fprintf(os.Stderr, "wasmforge: relaxed build constraints for %d _windows.go file(s)\n", count)
		}
		if rewrittenCount > 0 {
			fmt.Fprintf(os.Stderr, "wasmforge: rewritten build tags in %d file(s) to include wasip1\n", rewrittenCount)
		}
		if len(excluded) > 0 {
			fmt.Fprintf(os.Stderr, "wasmforge: excluded %d file(s) from wasip1\n", len(excluded))
		}
	}
	return contested, excluded, nil
}

// rewriteWindowsBuildTags rewrites //go:build header constraints in Go source
// files to include wasip1 where they reference windows:
//
//   - "//go:build darwin || linux || windows" → "//go:build darwin || linux || windows || wasip1"
//   - "//go:build !windows" → "//go:build !windows && !wasip1" (so wasip1 matches the windows path)
//
// Actually, the strategy is simpler: if the constraint includes "windows" as
// a positive term (not negated), add "|| wasip1" so wasip1 builds also pick up
// the file. If the constraint excludes windows ("!windows"), remove the
// negation for wasip1 context by transforming "!windows" → "!windows && !wasip1"
// injectBuildTag adds a //go:build constraint before the package line
// of a Go source file that has no existing build tag. This is needed when
// _windows.go files are renamed to _wfwin.go and lose their filename-based
// GOOS constraint.
func injectBuildTag(data []byte, constraint string) []byte {
	lines := strings.Split(string(data), "\n")
	// Check if the file already has a build tag.
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build ") {
			return data // Already has a build tag, don't inject another.
		}
		if strings.HasPrefix(trimmed, "package ") {
			break
		}
	}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") {
			tag := "//go:build " + constraint
			// Insert blank line + build tag before package line.
			newLines := make([]string, 0, len(lines)+2)
			newLines = append(newLines, lines[:i]...)
			newLines = append(newLines, tag, "")
			newLines = append(newLines, lines[i:]...)
			return []byte(strings.Join(newLines, "\n"))
		}
	}
	return data
}

// forceBuildTag replaces any existing //go:build line with the given constraint,
// or injects one if none exists. This is used when a _wasip1.go stub exists
// and we need to ensure the _wfwin.go file is windows-only.
func forceBuildTag(data []byte, constraint string) []byte {
	tag := "//go:build " + constraint
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build ") {
			lines[i] = tag
			return []byte(strings.Join(lines, "\n"))
		}
		if strings.HasPrefix(trimmed, "package ") {
			break
		}
	}
	// No existing build tag found, inject one.
	return injectBuildTag(data, constraint)
}

// — but actually, we WANT wasip1 to behave like windows, so we instead
// transform "!windows" constraints to also exclude wasip1, which means files
// with positive "windows" constraints will match wasip1, and stub files that
// are for non-Windows will properly exclude wasip1.
func rewriteWindowsBuildTags(data []byte) ([]byte, bool) {
	lines := strings.Split(string(data), "\n")
	changed := false
	hasGoBuild := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build ") {
			hasGoBuild = true
			constraint := strings.TrimPrefix(trimmed, "//go:build ")

			// If the constraint already mentions wasip1, skip.
			if strings.Contains(constraint, "wasip1") {
				continue
			}

			// Strategy: treat wasip1 as equivalent to windows.
			if strings.Contains(constraint, "windows") {
				// Detect architecture-specific constraints like
				// "(windows && amd64) || (windows && arm64)".
				// In these cases, simple replacement produces
				// "((windows || wasip1) && amd64)" which is false for
				// wasip1+wasm because wasm != amd64.
				//
				// Instead: if the constraint has amd64, add "|| wasip1"
				// at the end to include it in the 64-bit variant.
				// If it has 386/arm but NOT amd64, skip wasip1 entirely
				// (wasip1 should use the 64-bit variant).
				archSpecific := containsArch(constraint)
				var newConstraint string
				if archSpecific {
					// Architecture-specific constraints like
					// "(amd64 || arm64) && windows" rely on types and
					// behavior tied to a real architecture (amd64/arm64).
					// GOARCH=wasm doesn't match, so adding wasip1 either:
					// (a) enables files that use undefined arch-specific
					//     types (e.g., syscall.Win32FileAttributeData), or
					// (b) conflicts with _unsupported.go fallbacks that
					//     properly handle non-matching architectures.
					// Skip wasip1 for arch-specific constraints; the
					// fallback/unsupported variant will handle wasip1.
					continue
				} else {
					// No architecture constraint — replace windows with (windows || wasip1).
					newConstraint = strings.ReplaceAll(constraint, "windows", "(windows || wasip1)")
				}
				lines[i] = "//go:build " + newConstraint
				changed = true
			}
		}
		// Stop after the package declaration.
		if strings.HasPrefix(trimmed, "package ") {
			break
		}
	}

	// Handle old-style "// +build" tags when no "//go:build" was found.
	// If the file uses only "// +build windows", add a "//go:build" line
	// that takes precedence and includes wasip1.
	if !hasGoBuild {
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			var constraint string
			if strings.HasPrefix(trimmed, "// +build ") {
				constraint = strings.TrimPrefix(trimmed, "// +build ")
			} else if strings.HasPrefix(trimmed, "//+build ") {
				constraint = strings.TrimPrefix(trimmed, "//+build ")
			} else {
				if strings.HasPrefix(trimmed, "package ") {
					break
				}
				continue
			}
			if strings.Contains(constraint, "wasip1") {
				continue
			}
			if strings.Contains(constraint, "windows") {
				// Skip arch-specific constraints — see //go:build
				// handler above for rationale.
				if containsArch(constraint) {
					continue
				}
				newConstraint := convertPlusBuildToGoBuild(constraint)
				lines[i] = "//go:build " + newConstraint + "\n" + lines[i]
				changed = true
			}
		}
	}

	if changed {
		return []byte(strings.Join(lines, "\n")), true
	}
	return data, false
}

// convertPlusBuildToGoBuild converts an old-style "// +build" constraint
// to a "//go:build" constraint with wasip1 added where windows appears.
// In +build syntax: spaces = OR, commas = AND.
// Examples:
//
//	"windows" → "(windows || wasip1)"
//	"!windows" → "!(windows || wasip1)"
//	"windows,amd64" → "((windows || wasip1) && amd64)"
//	"darwin freebsd linux netbsd openbsd" → unchanged (no windows)
func convertPlusBuildToGoBuild(constraint string) string {
	// Split by spaces (OR groups).
	orGroups := strings.Fields(constraint)
	var goBuildParts []string
	for _, group := range orGroups {
		// Each group may have commas (AND terms).
		andTerms := strings.Split(group, ",")
		var goAndParts []string
		for _, term := range andTerms {
			if term == "windows" {
				goAndParts = append(goAndParts, "(windows || wasip1)")
			} else if term == "!windows" {
				goAndParts = append(goAndParts, "!(windows || wasip1)")
			} else {
				goAndParts = append(goAndParts, term)
			}
		}
		if len(goAndParts) == 1 {
			goBuildParts = append(goBuildParts, goAndParts[0])
		} else {
			goBuildParts = append(goBuildParts, "("+strings.Join(goAndParts, " && ")+")")
		}
	}
	return strings.Join(goBuildParts, " || ")
}

// rewriteSyscallTypeMismatches transforms syscall calls that use
// Windows-specific types to wasip1-compatible equivalents:
//   - syscall.Close(Handle) → syscall.CloseW(Handle)
//   - syscall.Write(syscall.Handle(x),...) → syscall.Write(int(x),...)
//   - syscall.Read(syscall.Handle(x),...) → syscall.Read(int(x),...)
//   - syscall.Seek(syscall.Handle(x),...) → syscall.Seek(int(x),...)
//
// This bridges Windows code that uses syscall.Handle where wasip1 expects int.
// Only applied to files originating from Windows-tagged sources.
func rewriteSyscallTypeMismatches(data []byte) []byte {
	// Close is unconditional: wasip1's syscall.Close takes int, not Handle,
	// while CloseW accepts Handle. Write/Read/Seek only need rewriting when
	// the argument is explicitly cast to syscall.Handle.
	data = bytes.ReplaceAll(data, []byte("syscall.Close("), []byte("syscall.CloseW("))
	data = bytes.ReplaceAll(data, []byte("syscall.Write(syscall.Handle("), []byte("syscall.Write(int("))
	data = bytes.ReplaceAll(data, []byte("syscall.Read(syscall.Handle("), []byte("syscall.Read(int("))
	data = bytes.ReplaceAll(data, []byte("syscall.Seek(syscall.Handle("), []byte("syscall.Seek(int("))
	return data
}

// hasRemainingHandleMismatches checks whether file data still contains
// Windows-specific type patterns that would fail on wasip1 after
// rewriteSyscallTypeMismatches has been applied. This catches cases like
// syscall.Handle in unsupported contexts or syscall.MustLoadDLL in init().
func hasRemainingHandleMismatches(data []byte) bool {
	return bytes.Contains(data, []byte("syscall.Handle(")) ||
		bytes.Contains(data, []byte("syscall.MustLoadDLL("))
}

// rewritePanicFallbacks parses a Go source file and replaces functions
// whose body is a single panic(...) call with zero-value return stubs.
// Returns the rewritten data and whether any changes were made.
func rewritePanicFallbacks(data []byte) ([]byte, bool) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", data, parser.ParseComments)
	if err != nil {
		return data, false
	}

	changed := false
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// Check for single-statement body that is panic(...)
		if len(fn.Body.List) != 1 {
			continue
		}
		exprStmt, ok := fn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			continue
		}
		callExpr, ok := exprStmt.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		ident, ok := callExpr.Fun.(*ast.Ident)
		if !ok || ident.Name != "panic" {
			continue
		}

		// Build replacement body with zero-value returns.
		var stmts []ast.Stmt
		if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
			vals := zeroReturnValues(fset, fn.Type.Results)
			var results []ast.Expr
			for _, v := range vals {
				results = append(results, &ast.Ident{Name: v})
			}
			stmts = append(stmts, &ast.ReturnStmt{Results: results})
		} else {
			// No return values — empty body replaces panic.
			stmts = append(stmts, &ast.ReturnStmt{})
		}
		fn.Body.List = stmts
		changed = true
	}

	if !changed {
		return data, false
	}
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, f); err != nil {
		return data, false
	}
	return buf.Bytes(), true
}

// containsArch returns true if the build constraint contains a specific
// Go architecture like amd64, 386, arm, arm64 (not wasm). This detects
// constraints like "(windows && amd64) || (windows && arm64)" which need
// special handling — wasip1 (GOARCH=wasm) won't match those arches.
func containsArch(constraint string) bool {
	arches := []string{"amd64", "386", "arm64", "arm"}
	for _, arch := range arches {
		if strings.Contains(constraint, arch) {
			return true
		}
	}
	return false
}

// fileHasArchConstraintNoWasm checks if file data contains a //go:build
// constraint with architecture terms (amd64, 386, arm64, arm) but NOT wasm.
// Such files won't compile for GOOS=wasip1 GOARCH=wasm since their arch
// constraints don't match.
func fileHasArchConstraintNoWasm(data []byte) bool {
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build ") {
			constraint := strings.TrimPrefix(trimmed, "//go:build ")
			if containsArch(constraint) && !strings.Contains(constraint, "wasm") {
				return true
			}
		}
		if strings.HasPrefix(trimmed, "package ") {
			break
		}
	}
	return false
}

// fileImportsSkippedModule checks whether a Go source file imports any of the
// given module paths. Used to detect _wfwin.go files that depend on vendor
// packages skipped during rewriting (e.g., go-winio). Such files cannot
// compile for wasip1 and must be forced to windows-only.
func fileImportsSkippedModule(data []byte, skipModules []string) bool {
	if len(skipModules) == 0 {
		return false
	}
	lines := strings.Split(string(data), "\n")
	inImportBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import (") {
			inImportBlock = true
			continue
		}
		if inImportBlock && trimmed == ")" {
			inImportBlock = false
			continue
		}
		if strings.HasPrefix(trimmed, "import ") || inImportBlock {
			// Extract quoted import path.
			if idx := strings.Index(trimmed, `"`); idx >= 0 {
				rest := trimmed[idx+1:]
				if end := strings.Index(rest, `"`); end >= 0 {
					importPath := rest[:end]
					for _, skip := range skipModules {
						if strings.HasPrefix(importPath, skip) {
							return true
						}
					}
				}
			}
		}
		// Stop scanning after import declarations.
		if !inImportBlock && (strings.HasPrefix(trimmed, "func ") ||
			strings.HasPrefix(trimmed, "type ") ||
			strings.HasPrefix(trimmed, "var ") ||
			strings.HasPrefix(trimmed, "const ")) {
			break
		}
	}
	return false
}

// fileExcludesWasip1FromData checks in-memory file data for a //go:build
// constraint that excludes GOOS=wasip1. Used during tag rewriting to detect
// files being excluded before they are written to disk.
func fileExcludesWasip1FromData(data []byte) bool {
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build ") {
			constraint := strings.TrimPrefix(trimmed, "//go:build ")
			// Check for explicit "!wasip1" or "!(windows || wasip1)".
			if strings.Contains(constraint, "!wasip1") ||
				strings.Contains(constraint, "!(windows || wasip1)") {
				return true
			}
			// Check for wasip1 inside a negated expression like
			// "!(linux || darwin || (windows || wasip1))". If the
			// constraint starts with "!" and contains "wasip1" inside,
			// and does NOT contain a positive "|| wasip1)" outside a
			// negation, then wasip1 is excluded.
			if strings.Contains(constraint, "wasip1") {
				if constraintExcludesWasip1(constraint) {
					return true
				}
			}
		}
		// Also check old-style build tags (both "// +build" and "//+build")
		// for explicit !windows which excludes wasip1.
		if strings.HasPrefix(trimmed, "// +build ") || strings.HasPrefix(trimmed, "//+build ") {
			c := trimmed
			c = strings.TrimPrefix(c, "// +build ")
			c = strings.TrimPrefix(c, "//+build ")
			if strings.Contains(c, "!windows") {
				return true
			}
		}
		if strings.HasPrefix(trimmed, "package ") {
			break
		}
	}
	return false
}

// constraintExcludesWasip1 checks if a build constraint expression excludes
// wasip1 by analyzing the nesting of wasip1 within negations. This handles
// cases like "!(linux || darwin || (windows || wasip1))" where wasip1 appears
// only inside negated groups.
func constraintExcludesWasip1(constraint string) bool {
	// Find all occurrences of "wasip1" and check if each is inside a negation.
	idx := 0
	for {
		pos := strings.Index(constraint[idx:], "wasip1")
		if pos < 0 {
			break
		}
		absPos := idx + pos

		// Count the nesting depth of negations at this position.
		// Walk backwards counting unmatched '!' before '(' groups.
		depth := 0
		negDepth := 0
		for i := absPos - 1; i >= 0; i-- {
			switch constraint[i] {
			case ')':
				depth++
			case '(':
				depth--
				if depth < 0 {
					// We've exited a group. Check if it was negated.
					if i > 0 && constraint[i-1] == '!' {
						negDepth++
						i-- // skip the '!'
					}
					depth = 0
				}
			}
		}

		// If wasip1 is inside at least one negation, it's excluded.
		if negDepth > 0 {
			return true
		}

		idx = absPos + len("wasip1")
	}

	return false
}

// fileExcludesWasip1 checks whether a Go source file has a //go:build constraint
// that excludes GOOS=wasip1. This detects non-windows stub files that were
// rewritten by the first pass (e.g., "!windows" → "!(windows || wasip1)").
func fileExcludesWasip1(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build ") {
			constraint := strings.TrimPrefix(trimmed, "//go:build ")
			// Check for negated wasip1: "!wasip1" or "!(windows || wasip1)"
			if strings.Contains(constraint, "!wasip1") ||
				strings.Contains(constraint, "!(windows || wasip1)") {
				return true
			}
		}
		// Also check old-style build tags for explicit !windows (which
		// we can treat as excluding wasip1 since we want wasip1=windows).
		// Handle both "// +build" (with space) and "//+build" (no space).
		if strings.HasPrefix(trimmed, "// +build ") {
			constraint := strings.TrimPrefix(trimmed, "// +build ")
			if strings.Contains(constraint, "!windows") {
				return true
			}
		} else if strings.HasPrefix(trimmed, "//+build ") {
			constraint := strings.TrimPrefix(trimmed, "//+build ")
			if strings.Contains(constraint, "!windows") {
				return true
			}
		}
		if strings.HasPrefix(trimmed, "package ") {
			break
		}
	}
	return false
}

// hasWindowsSuffix reports whether the Go file name (without .go extension)
// has an implicit GOOS=windows build constraint from the filename convention.
// Matches: foo_windows, foo_windows_amd64, foo_windows_arm64, etc.
func hasWindowsSuffix(name string) bool {
	parts := strings.Split(name, "_")
	n := len(parts)
	if n < 2 {
		return false
	}
	if parts[n-1] == "windows" {
		return true
	}
	if n >= 3 && parts[n-2] == "windows" {
		return isKnownGoArch(parts[n-1])
	}
	return false
}

// removeWindowsSuffix strips the _windows (and optional _GOARCH) suffix from
// a Go file name. Returns the name with the platform constraint removed.
func removeWindowsSuffix(name string) string {
	parts := strings.Split(name, "_")
	n := len(parts)
	if parts[n-1] == "windows" {
		return strings.Join(parts[:n-1], "_")
	}
	if n >= 3 && parts[n-2] == "windows" {
		return strings.Join(parts[:n-2], "_")
	}
	return name
}

// findGoModRoot walks up from dir looking for a go.mod file and returns
// the directory containing it. Returns "" if no go.mod is found.
func findGoModRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func isKnownGoArch(s string) bool {
	switch s {
	case "amd64", "386", "arm", "arm64", "mips", "mips64", "mipsle", "mips64le",
		"ppc64", "ppc64le", "riscv64", "s390x", "wasm", "loong64":
		return true
	}
	return false
}

// restoreNeededStubs parses go build stderr output and restores wasip1 stubs
// for packages that had compilation errors. Returns the number of stubs restored.
func restoreNeededStubs(stderr []byte, contested []contestedPair, workDir string, verbose bool) int {
	errorOutput := string(stderr)
	restored := 0

	for i := range contested {
		pair := &contested[i]

		// Check if errors reference this wfwin file or its package directory.
		wfwinBase := filepath.Base(pair.wfwinPath)
		var relDir string
		if workDir != "" {
			relDir, _ = filepath.Rel(workDir, pair.pkgDir)
		}

		needsStub := strings.Contains(errorOutput, wfwinBase)
		if !needsStub && relDir != "" && relDir != "." {
			// Also check if any file in the same package had errors.
			needsStub = strings.Contains(errorOutput, relDir+"/") ||
				strings.Contains(errorOutput, relDir+string(filepath.Separator))
		}

		if needsStub {
			// Restore the stub.
			if err := os.Rename(pair.backupPath, pair.stubPath); err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: warning: could not restore %s: %v\n",
						filepath.Base(pair.stubPath), err)
				}
				continue // Do not mark as restored; backup remains for cleanup.
			}
			// The _wfwin.go was written with "windows || wasip1" tags by
			// relaxWindowsBuildConstraints (optimistic path). Now that we know
			// the real code can't compile for wasip1, force it windows-only so
			// the restored stub handles wasip1.
			if data, err := os.ReadFile(pair.wfwinPath); err == nil {
				data = forceBuildTag(data, "windows")
				if werr := os.WriteFile(pair.wfwinPath, data, 0o644); werr != nil && verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: warning: could not retag %s: %v\n",
						filepath.Base(pair.wfwinPath), werr)
				}
			}
			pair.backupPath = "" // Mark as restored (no cleanup needed).
			restored++
			if verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: restoring %s (real code can't compile for wasip1 yet)\n",
					filepath.Base(pair.stubPath))
			}
		} else if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: keeping %s dropped (no errors in package)\n",
				filepath.Base(pair.stubPath))
		}
	}
	return restored
}

// cleanupStubBackups removes any remaining .wfstub backup files.
func cleanupStubBackups(contested []contestedPair) {
	for _, pair := range contested {
		if pair.backupPath != "" {
			os.Remove(pair.backupPath)
		}
	}
}

// undefinedSymbolRe matches Go compiler "undefined: SymbolName" errors.
// Format: ./path/to/file.go:42:15: undefined: FunctionName
var undefinedSymbolRe = regexp.MustCompile(`^(.+\.go):\d+:\d+: undefined: (\w+)$`)

// undefinedMethodRe matches Go compiler "has no field or method" errors.
// Format: ./path/to/file.go:42:15: expr.method undefined (type T has no field or method method)
var undefinedMethodRe = regexp.MustCompile(`^(.+\.go):\d+:\d+: .+ has no field or method (\w+)\)$`)

// generateAutoStubs parses build errors for undefined symbols, locates them in
// excluded source files, and generates _wfstub_wasip1.go stub files with
// zero-value return bodies. For packages in the read-only Go module cache,
// the module is copied to tmpDir and a replace directive is injected into
// go.mod. Returns the number of stub files generated.
func generateAutoStubs(stderr []byte, excluded []excludedFile, workDir, tmpDir string, verbose bool) (int, error) {
	if len(excluded) == 0 {
		return 0, nil
	}

	// Parse undefined symbols from stderr, grouped by package directory.
	undefinedByPkg := parseUndefinedSymbols(stderr, workDir)
	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: auto-stub: parsed %d package(s) with undefined symbols, %d excluded file(s)\n", len(undefinedByPkg), len(excluded))
		for pkg, syms := range undefinedByPkg {
			symNames := make([]string, 0, len(syms))
			for s := range syms {
				symNames = append(symNames, s)
			}
			fmt.Fprintf(os.Stderr, "wasmforge: auto-stub:   pkg=%s syms=%v\n", pkg, symNames)
		}
	}
	if len(undefinedByPkg) == 0 {
		return 0, nil
	}

	// Build a map from package directory → excluded files in that package.
	excludedByPkg := map[string][]excludedFile{}
	for _, ef := range excluded {
		excludedByPkg[ef.pkgDir] = append(excludedByPkg[ef.pkgDir], ef)
	}

	generated := 0
	for pkgDir, symbols := range undefinedByPkg {
		exFiles, ok := excludedByPkg[pkgDir]
		if !ok {
			// No excluded files in this package — the error file paths
			// may be relative while excluded paths are absolute, or vice
			// versa. Try resolving via relative path comparison.
			for dir, files := range excludedByPkg {
				rel1, err1 := filepath.Rel(workDir, dir)
				rel2, err2 := filepath.Rel(workDir, pkgDir)
				if err1 == nil && err2 == nil && rel1 == rel2 {
					exFiles = files
					ok = true
					break
				}
			}
			if !ok {
				// No excluded files in this package. If it's in the
				// module cache, copy it to a writable location,
				// generate stubs, and inject a replace directive.
				if isModuleCachePkg(pkgDir) {
					gomodPath := filepath.Join(workDir, "go.mod")
					n, err := generateModCacheStub(pkgDir, symbols, tmpDir, gomodPath, verbose)
					if err != nil && verbose {
						fmt.Fprintf(os.Stderr, "wasmforge: auto-stub: modcache warning: %v\n", err)
					}
					generated += n
				}
				continue
			}
		}

		// Parse all excluded files in this package to extract declarations.
		fset := token.NewFileSet()
		var allDecls []ast.Decl
		var pkgName string
		// Collect imports from excluded files (keyed by import path to deduplicate).
		importMap := map[string]*ast.ImportSpec{}
		for _, ef := range exFiles {
			// Use stored content if available (file may have been removed
			// during processing). When data is nil, ParseFile reads from disk.
			var src interface{}
			if ef.data != nil {
				src = ef.data
			}
			f, err := parser.ParseFile(fset, ef.path, src, parser.ParseComments)
			if err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: auto-stub: failed to parse %s: %v\n", ef.path, err)
				}
				continue
			}
			if pkgName == "" {
				pkgName = f.Name.Name
			}
			for _, imp := range f.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if _, exists := importMap[path]; !exists {
					importMap[path] = imp
				}
			}
			allDecls = append(allDecls, f.Decls...)
		}

		if pkgName == "" || len(allDecls) == 0 {
			continue
		}

		// Generate stub file with only the UNDEFINED declarations from
		// excluded files. The retry loop (up to 3 attempts) handles
		// cascading dependencies (e.g., undefined type needed by a stub).
		stubPath := filepath.Join(pkgDir, "wfstub_wasip1.go")

		// If a stub already exists (from a previous iteration), check if
		// we have new symbols to add. If so, delete and regenerate.
		if existingData, err := os.ReadFile(stubPath); err == nil {
			hasNew := false
			for sym := range symbols {
				if !strings.Contains(string(existingData), sym) {
					hasNew = true
					break
				}
			}
			if !hasNew {
				continue
			}
			os.Remove(stubPath)
		}

		stubContent, err := generateStubFile(fset, pkgName, allDecls, importMap, symbols)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: auto-stub: failed to generate %s: %v\n", stubPath, err)
			}
			continue
		}

		if err := os.WriteFile(stubPath, stubContent, 0o644); err != nil {
			return generated, fmt.Errorf("writing stub %s: %w", stubPath, err)
		}

		generated++
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: auto-stub: generated %s\n", stubPath)
		}
	}

	return generated, nil
}

// isModuleCachePkg returns true if pkgDir appears to be inside the Go module
// cache (e.g., ~/go/pkg/mod/...). These directories are read-only and cannot
// have stub files written directly.
func isModuleCachePkg(pkgDir string) bool {
	return strings.Contains(pkgDir, filepath.Join("pkg", "mod"))
}

// generateModCacheStub handles undefined symbols in read-only Go module cache
// packages by copying the module to a writable location, generating stubs, and
// injecting a replace directive into go.mod. Returns the number of stubs
// generated (0 or 1).
func generateModCacheStub(pkgDir string, symbols map[string]bool, tmpDir, gomodPath string, verbose bool) (int, error) {
	// Parse the module root, path, and version from the cache directory.
	modRoot, modPath, version, ok := parseModCachePath(pkgDir)
	if !ok {
		return 0, fmt.Errorf("cannot parse module cache path: %s", pkgDir)
	}

	// Determine the sub-package path within the module (if any).
	subPkg := ""
	if pkgDir != modRoot {
		rel, err := filepath.Rel(modRoot, pkgDir)
		if err == nil && rel != "." {
			subPkg = rel
		}
	}

	// Create a writable copy of the module.
	modCopyDir := filepath.Join(tmpDir, "modreplace", filepath.FromSlash(modPath))
	if err := os.MkdirAll(filepath.Dir(modCopyDir), 0o755); err != nil {
		return 0, fmt.Errorf("creating modreplace dir: %w", err)
	}

	// Check if we've already copied this module (from a previous iteration).
	if _, err := os.Stat(modCopyDir); os.IsNotExist(err) {
		if err := copyDir(modRoot, modCopyDir); err != nil {
			return 0, fmt.Errorf("copying module %s: %w", modPath, err)
		}
	}

	// Determine the package directory in the writable copy.
	writablePkgDir := modCopyDir
	if subPkg != "" {
		writablePkgDir = filepath.Join(modCopyDir, subPkg)
	}

	// Scan all Go files in the package to find declarations of undefined symbols.
	entries, err := os.ReadDir(writablePkgDir)
	if err != nil {
		return 0, fmt.Errorf("reading module copy pkg %s: %w", writablePkgDir, err)
	}

	fset := token.NewFileSet()
	var allDecls []ast.Decl
	var pkgName string
	importMap := map[string]*ast.ImportSpec{}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		filePath := filepath.Join(writablePkgDir, entry.Name())
		f, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
		if err != nil {
			continue
		}
		if pkgName == "" {
			pkgName = f.Name.Name
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if _, exists := importMap[p]; !exists {
				importMap[p] = imp
			}
		}
		allDecls = append(allDecls, f.Decls...)
	}

	if pkgName == "" || len(allDecls) == 0 {
		return 0, nil
	}

	// Check if a stub already exists with all needed symbols.
	stubPath := filepath.Join(writablePkgDir, "wfstub_wasip1.go")
	if existingData, err := os.ReadFile(stubPath); err == nil {
		hasNew := false
		for sym := range symbols {
			if !strings.Contains(string(existingData), sym) {
				hasNew = true
				break
			}
		}
		if !hasNew {
			return 0, nil
		}
		os.Remove(stubPath)
	}

	stubContent, err := generateStubFile(fset, pkgName, allDecls, importMap, symbols)
	if err != nil {
		return 0, fmt.Errorf("generating modcache stub for %s: %w", modPath, err)
	}

	if err := os.WriteFile(stubPath, stubContent, 0o644); err != nil {
		return 0, fmt.Errorf("writing modcache stub: %w", err)
	}

	// Inject replace directive into the project's go.mod.
	gomodData, err := os.ReadFile(gomodPath)
	if err != nil {
		return 0, fmt.Errorf("reading go.mod: %w", err)
	}
	replaceDirective := fmt.Sprintf("replace %s %s => %s", modPath, version, modCopyDir)
	if !strings.Contains(string(gomodData), replaceDirective) {
		newContent := strings.TrimRight(string(gomodData), "\n") + "\n" + replaceDirective + "\n"
		if err := os.WriteFile(gomodPath, []byte(newContent), 0o644); err != nil {
			return 0, fmt.Errorf("writing go.mod replace: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: auto-stub: injected replace %s %s => %s\n", modPath, version, modCopyDir)
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: auto-stub: generated %s (modcache copy)\n", stubPath)
	}

	return 1, nil
}

// parseModCachePath extracts the module root directory, module path, and version
// from a Go module cache path like ~/go/pkg/mod/github.com/foo/bar@v1.0.0/sub.
func parseModCachePath(pkgDir string) (modRoot, modPath, version string, ok bool) {
	d := pkgDir
	for {
		base := filepath.Base(d)
		if atIdx := strings.LastIndex(base, "@"); atIdx > 0 {
			version = base[atIdx+1:]
			modRoot = d
			// Find the GOMODCACHE boundary (pkg/mod/).
			sep := string(filepath.Separator)
			marker := filepath.Join("pkg", "mod") + sep
			idx := strings.Index(d, marker)
			if idx < 0 {
				return "", "", "", false
			}
			modCacheEnd := idx + len(marker)
			modPathDir := d[modCacheEnd:]
			// Remove the @version suffix from the last component.
			modPathDir = modPathDir[:len(modPathDir)-len("@"+version)]
			modPath = filepath.ToSlash(modPathDir)
			// Decode module cache uppercase encoding (!x → X).
			modPath = decodeModCachePath(modPath)
			return modRoot, modPath, version, true
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return "", "", "", false
}

// decodeModCachePath reverses the Go module cache encoding where uppercase
// letters are stored as !<lowercase>.
func decodeModCachePath(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '!' && i+1 < len(s) {
			out.WriteByte(s[i+1] - 'a' + 'A')
			i++
		} else {
			out.WriteByte(s[i])
		}
	}
	return out.String()
}

// fixModCachePanicFallbacks scans Go module cache dependencies for platform
// fallback files that compile for wasip1 but panic at runtime with
// "Not implemented". The pattern is: a package has _windows.go with real
// implementation and a generic fallback (e.g., isatty.go with
// !windows,!linux,!darwin constraint) that contains panic("Not implemented").
// For wasip1 builds the fallback is selected instead of the Windows code.
//
// For each such package, this function copies the module to a writable
// location, applies build constraint relaxation (renaming _windows.go so it
// is selected for wasip1), and injects a replace directive.
func fixModCachePanicFallbacks(workDir, goBin string, buildEnv []string, tmpDir string, win32APIs, verbose bool) error {
	// Use go list -deps to discover all dependency package directories.
	cmd := exec.Command(goBin, "list", "-deps", "-e", "-f", "{{.Dir}}", "./...")
	cmd.Dir = workDir
	cmd.Env = buildEnv
	out, err := cmd.Output()
	if err != nil {
		// go list may fail for some deps; process what we can.
		if len(out) == 0 {
			return nil
		}
	}

	gomodPath := filepath.Join(workDir, "go.mod")
	// Track which module roots we've already processed to avoid duplicates.
	processedModules := map[string]bool{}
	fixed := 0

	for _, dir := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dir = strings.TrimSpace(dir)
		if dir == "" || !isModuleCachePkg(dir) {
			continue
		}

		// Check if this package has the panic fallback pattern.
		if !hasPanicFallbackPattern(dir) {
			continue
		}

		// Parse module root, path, and version.
		modRoot, modPath, version, ok := parseModCachePath(dir)
		if !ok {
			continue
		}
		if processedModules[modRoot] {
			continue
		}
		processedModules[modRoot] = true

		// Copy the entire module to a writable location.
		modCopyDir := filepath.Join(tmpDir, "modreplace", filepath.FromSlash(modPath))
		if _, err := os.Stat(modCopyDir); os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(modCopyDir), 0o755); err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: modcache fix: mkdir %s: %v\n", modCopyDir, err)
				}
				continue
			}
			if err := copyDir(modRoot, modCopyDir); err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: modcache fix: copy %s: %v\n", modPath, err)
				}
				continue
			}
		}

		// Ensure the copy has a go.mod (pre-module packages lack one).
		copyGoMod := filepath.Join(modCopyDir, "go.mod")
		if _, err := os.Stat(copyGoMod); os.IsNotExist(err) {
			gomodContent := fmt.Sprintf("module %s\n\ngo 1.21\n", modPath)
			if err := os.WriteFile(copyGoMod, []byte(gomodContent), 0o644); err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: modcache fix: write go.mod for %s: %v\n", modPath, err)
				}
				continue
			}
		}

		if win32APIs {
			// With Win32 APIs: apply build constraint relaxation so the
			// Windows implementation is used (compiles with sysshim).
			if _, _, err := relaxWindowsBuildConstraints(modCopyDir, verbose); err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: modcache fix: relax constraints for %s: %v\n", modPath, err)
				}
				continue
			}
		} else {
			// Without Win32 APIs: replace panic() in fallback files with
			// safe no-op returns. The Windows implementation uses DLL
			// loading which won't compile without Win32 support.
			if err := applyPanicFallbackRewrite(modCopyDir); err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: modcache fix: rewrite panics for %s: %v\n", modPath, err)
				}
				continue
			}
		}

		// Inject replace directive into the project's go.mod.
		gomodData, err := os.ReadFile(gomodPath)
		if err != nil {
			continue
		}
		replaceDirective := fmt.Sprintf("replace %s %s => %s", modPath, version, modCopyDir)
		if !strings.Contains(string(gomodData), replaceDirective) {
			newContent := strings.TrimRight(string(gomodData), "\n") + "\n" + replaceDirective + "\n"
			if err := os.WriteFile(gomodPath, []byte(newContent), 0o644); err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: modcache fix: write go.mod: %v\n", err)
				}
				continue
			}
		}

		fixed++
		if verbose {
			if win32APIs {
				fmt.Fprintf(os.Stderr, "wasmforge: modcache fix: %s — relaxed build constraints to use Windows impl\n", modPath)
			} else {
				fmt.Fprintf(os.Stderr, "wasmforge: modcache fix: %s — replaced panic fallbacks with no-op returns\n", modPath)
			}
		}
	}

	if verbose && fixed > 0 {
		fmt.Fprintf(os.Stderr, "wasmforge: modcache fix: fixed %d module(s) with panic fallbacks\n", fixed)
	}
	return nil
}

// applyPanicFallbackRewrite walks a module directory and applies
// rewritePanicFallbacks to each Go source file containing panic().
func applyPanicFallbackRewrite(modDir string) error {
	return filepath.Walk(modDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if !bytes.Contains(data, []byte(`panic(`)) {
			return nil
		}
		if newData, changed := rewritePanicFallbacks(data); changed {
			if err := os.WriteFile(path, newData, 0o644); err != nil {
				return fmt.Errorf("writing rewritten %s: %w", path, err)
			}
		}
		return nil
	})
}

// hasPanicFallbackPattern checks if a package directory contains _windows.go
// implementation files alongside a fallback file that contains
// panic("Not implemented") or panic("not implemented") and would be selected
// for wasip1 builds.
func hasPanicFallbackPattern(pkgDir string) bool {
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return false
	}

	// Build a set of stems that have _windows.go implementations.
	windowsStems := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".go")
		if hasWindowsSuffix(name) {
			stem := removeWindowsSuffix(name)
			windowsStems[stem] = true
		}
	}
	if len(windowsStems) == 0 {
		return false
	}

	// Check non-Windows files for panic("Not implemented").
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".go")
		if hasWindowsSuffix(name) {
			continue
		}
		// Only check files whose stem matches a _windows.go file.
		if !windowsStems[name] {
			continue
		}

		data, err := os.ReadFile(filepath.Join(pkgDir, e.Name()))
		if err != nil {
			continue
		}
		if bytes.Contains(data, []byte(`panic("Not implemented")`)) ||
			bytes.Contains(data, []byte(`panic("not implemented")`)) {
			return true
		}
	}
	return false
}

// parseUndefinedSymbols extracts undefined symbol names from Go compiler stderr
// output and groups them by package directory.
func parseUndefinedSymbols(stderr []byte, workDir string) map[string]map[string]bool {
	result := map[string]map[string]bool{}
	lines := strings.Split(string(stderr), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		var filePath, symbol string

		// Try "undefined: SYMBOL" pattern first.
		if matches := undefinedSymbolRe.FindStringSubmatch(line); matches != nil {
			filePath = matches[1]
			symbol = matches[2]
		} else if matches := undefinedMethodRe.FindStringSubmatch(line); matches != nil {
			// Try "has no field or method METHOD" pattern.
			filePath = matches[1]
			symbol = matches[2]
		} else {
			continue
		}

		// Resolve the file path to get the package directory.
		if !filepath.IsAbs(filePath) && workDir != "" {
			filePath = filepath.Join(workDir, filePath)
		}
		pkgDir := filepath.Dir(filePath)

		if result[pkgDir] == nil {
			result[pkgDir] = map[string]bool{}
		}
		result[pkgDir][symbol] = true
	}

	return result
}

// generateStubFile creates the content of a _wfstub_wasip1.go file containing
// stub implementations for all declarations found in the excluded files.
func generateStubFile(fset *token.FileSet, pkgName string, decls []ast.Decl, importMap map[string]*ast.ImportSpec, undefinedSymbols map[string]bool) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString("//go:build wasip1\n\n")
	buf.WriteString("package " + pkgName + "\n\n")

	// Collect all generated declarations to determine needed imports.
	// Track seen declaration names to avoid duplicates (multiple excluded
	// files may define the same symbol).
	var genDecls []string
	seenDecls := map[string]bool{}
	needsErrors := false

	for _, decl := range decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			// Copy type, const, and var declarations — only those that
			// are actually undefined to avoid redeclaration conflicts
			// with symbols from non-excluded files.
			for _, spec := range d.Specs {
				var specBuf bytes.Buffer
				var declName string
				switch s := spec.(type) {
				case *ast.TypeSpec:
					declName = s.Name.Name
					if !undefinedSymbols[declName] || seenDecls[declName] {
						continue
					}
					// Copy the full type declaration.
					specBuf.WriteString("type ")
					if err := printer.Fprint(&specBuf, fset, s); err != nil {
						continue
					}
					specBuf.WriteString("\n")

				case *ast.ValueSpec:
					// Use first name as dedup key.
					if len(s.Names) > 0 {
						declName = s.Names[0].Name
					}
					if declName == "" || !undefinedSymbols[declName] || seenDecls[declName] {
						continue
					}
					// Copy const/var declarations.
					keyword := "var"
					if d.Tok == token.CONST {
						keyword = "const"
					}
					specBuf.WriteString(keyword + " ")
					if err := printer.Fprint(&specBuf, fset, s); err != nil {
						continue
					}
					specBuf.WriteString("\n")
				}
				if specBuf.Len() > 0 {
					if declName != "" {
						seenDecls[declName] = true
					}
					genDecls = append(genDecls, specBuf.String())
				}
			}

		case *ast.FuncDecl:
			// Dedup key: for methods, use "RecvType.Name"; for funcs, use "Name".
			declName := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) > 0 {
				var recvBuf bytes.Buffer
				printer.Fprint(&recvBuf, fset, d.Recv.List[0].Type)
				declName = recvBuf.String() + "." + d.Name.Name
			}
			// Only include functions/methods that are actually undefined.
			if !undefinedSymbols[d.Name.Name] || seenDecls[declName] {
				continue
			}
			seenDecls[declName] = true

			// Generate function with zero-value return body.
			var funcBuf bytes.Buffer
			funcBuf.WriteString("func ")

			// Method receiver.
			if d.Recv != nil && len(d.Recv.List) > 0 {
				funcBuf.WriteString("(")
				if err := printer.Fprint(&funcBuf, fset, d.Recv.List[0].Type); err != nil {
					continue
				}
				funcBuf.WriteString(") ")
			}

			funcBuf.WriteString(d.Name.Name)

			// Type parameters (Go generics).
			if d.Type.TypeParams != nil {
				funcBuf.WriteString("[")
				if err := printer.Fprint(&funcBuf, fset, d.Type.TypeParams); err != nil {
					continue
				}
				funcBuf.WriteString("]")
			}

			// Parameters.
			funcBuf.WriteString("(")
			if d.Type.Params != nil {
				if err := printFieldList(&funcBuf, fset, d.Type.Params); err != nil {
					continue
				}
			}
			funcBuf.WriteString(")")

			// Return types.
			if d.Type.Results != nil && len(d.Type.Results.List) > 0 {
				funcBuf.WriteString(" ")
				if len(d.Type.Results.List) == 1 && len(d.Type.Results.List[0].Names) == 0 {
					if err := printer.Fprint(&funcBuf, fset, d.Type.Results.List[0].Type); err != nil {
						continue
					}
				} else {
					funcBuf.WriteString("(")
					if err := printFieldList(&funcBuf, fset, d.Type.Results); err != nil {
						continue
					}
					funcBuf.WriteString(")")
				}
			}

			// Generate zero-value return body.
			funcBuf.WriteString(" {\n")
			if d.Type.Results != nil && len(d.Type.Results.List) > 0 {
				returnVals := zeroReturnValues(fset, d.Type.Results)
				for _, rv := range returnVals {
					if rv == `errors.New("not supported on wasip1")` {
						needsErrors = true
					}
				}
				funcBuf.WriteString("\treturn " + strings.Join(returnVals, ", ") + "\n")
			}
			funcBuf.WriteString("}\n")
			genDecls = append(genDecls, funcBuf.String())
		}
	}

	if len(genDecls) == 0 {
		return nil, fmt.Errorf("no declarations to stub")
	}

	// Only emit imports that are actually used in the generated stubs.
	// Since stubs use zero values (nil, 0, false, ""), the only import
	// typically needed is "errors" for error-returning functions.
	// Including unused imports causes compilation failures.
	stubImports := map[string]*ast.ImportSpec{}
	if needsErrors {
		stubImports["errors"] = &ast.ImportSpec{
			Path: &ast.BasicLit{Kind: token.STRING, Value: `"errors"`},
		}
	}
	// Scan generated declarations for package-qualified identifiers
	// (e.g., "syscall.Handle") and include those imports.
	genText := strings.Join(genDecls, "\n")
	for importPath, imp := range importMap {
		// Determine the package name used in code.
		pkgAlias := filepath.Base(importPath) // default: last segment
		if imp.Name != nil {
			pkgAlias = imp.Name.Name
		}
		// If the generated code references this package name followed by '.',
		// include the import.
		if strings.Contains(genText, pkgAlias+".") {
			stubImports[importPath] = imp
		}
	}
	if len(stubImports) > 0 {
		buf.WriteString("import (\n")
		for _, imp := range stubImports {
			buf.WriteString("\t")
			if imp.Name != nil {
				buf.WriteString(imp.Name.Name + " ")
			}
			buf.WriteString(imp.Path.Value + "\n")
		}
		buf.WriteString(")\n\n")
	}

	for _, d := range genDecls {
		buf.WriteString(d)
		buf.WriteString("\n")
	}

	return buf.Bytes(), nil
}

// printFieldList prints a FieldList (params or results) as comma-separated fields.
func printFieldList(buf *bytes.Buffer, fset *token.FileSet, fl *ast.FieldList) error {
	for i, field := range fl.List {
		if i > 0 {
			buf.WriteString(", ")
		}
		// Named parameters.
		if len(field.Names) > 0 {
			for j, name := range field.Names {
				if j > 0 {
					buf.WriteString(", ")
				}
				buf.WriteString(name.Name)
			}
			buf.WriteString(" ")
		}
		if err := printer.Fprint(buf, fset, field.Type); err != nil {
			return err
		}
	}
	return nil
}

// zeroReturnValues generates zero-value expressions for each return type in a
// function's result list.
func zeroReturnValues(fset *token.FileSet, results *ast.FieldList) []string {
	var vals []string
	for _, field := range results.List {
		zv := zeroValueForType(fset, field.Type)
		// If the field has multiple names, emit the zero value for each.
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		for i := 0; i < count; i++ {
			vals = append(vals, zv)
		}
	}
	return vals
}

// zeroValueForType returns a zero-value expression string for the given AST type.
func zeroValueForType(fset *token.FileSet, expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		switch t.Name {
		case "error":
			return "nil"
		case "bool":
			return "false"
		case "string":
			return `""`
		case "int", "int8", "int16", "int32", "int64",
			"uint", "uint8", "uint16", "uint32", "uint64",
			"uintptr", "float32", "float64",
			"byte", "rune":
			return "0"
		default:
			// Named type — could be a struct, interface, or primitive
			// alias (e.g., syscall.Errno). *new(T) is the universal
			// zero value that works for any Go type.
			return "*new(" + t.Name + ")"
		}

	case *ast.StarExpr:
		return "nil"

	case *ast.ArrayType:
		return "nil"

	case *ast.MapType:
		return "nil"

	case *ast.ChanType:
		return "nil"

	case *ast.FuncType:
		return "nil"

	case *ast.InterfaceType:
		return "nil"

	case *ast.SelectorExpr:
		// e.g., pkg.Type — could be a struct, interface, or primitive alias.
		// *new(pkg.Type) is the universal zero value for any Go type.
		var buf bytes.Buffer
		printer.Fprint(&buf, fset, t)
		return "*new(" + buf.String() + ")"

	case *ast.Ellipsis:
		// Variadic — shouldn't appear in results, but handle it.
		return "nil"

	default:
		// Fallback: try to print the type and use *new(T).
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, expr); err != nil {
			return "nil"
		}
		return "*new(" + buf.String() + ")"
	}
}

// rewritePlatformConstants walks all .go files in dir and replaces
// runtime.GOOS / runtime.GOARCH selector expressions with string literals
// matching the target platform. This allows the WASM guest to report the
// correct platform to remote servers without patching the Go runtime (which
// is fundamentally broken — see MEMORY.md).
func rewritePlatformConstants(dir, targetGOOS, targetGOARCH string, verbose bool) error {
	rewriteGOOS := targetGOOS != "wasip1"
	rewriteGOARCH := targetGOARCH != "wasm"
	if !rewriteGOOS && !rewriteGOARCH {
		return nil // Nothing to rewrite.
	}

	count := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip the sysshim vendor directory — it provides types, not
		// platform detection, and rewriting it could break imports.
		if info.IsDir() && strings.Contains(path, filepath.Join("vendor", "golang.org", "x", "sys")) {
			return filepath.SkipDir
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		changed, ferr := rewritePlatformConstantsInFile(path, targetGOOS, targetGOARCH, rewriteGOOS, rewriteGOARCH)
		if ferr != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: warning: skipping %s: %v\n", path, ferr)
			}
			return nil // Skip unparseable files.
		}
		if changed {
			count++
		}
		return nil
	})
	if err != nil {
		return err
	}

	if verbose && count > 0 {
		parts := make([]string, 0, 2)
		if rewriteGOOS {
			parts = append(parts, fmt.Sprintf("runtime.GOOS → %q", targetGOOS))
		}
		if rewriteGOARCH {
			parts = append(parts, fmt.Sprintf("runtime.GOARCH → %q", targetGOARCH))
		}
		fmt.Fprintf(os.Stderr, "wasmforge: rewriting %s in %d file(s)\n", strings.Join(parts, " and "), count)
	}
	return nil
}

// replacement records a byte range [start, end) to be replaced with a literal.
type replacement struct {
	start, end int
	literal    string
}

// rewritePlatformConstantsInFile rewrites runtime.GOOS and/or runtime.GOARCH
// in a single Go source file using position-based text replacement (preserves
// original formatting — no go/printer reformatting).
func rewritePlatformConstantsInFile(path, targetGOOS, targetGOARCH string, rewriteGOOS, rewriteGOARCH bool) (bool, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return false, err
	}

	localName, isDot, hasRuntime := findRuntimeImport(f)
	if !hasRuntime || isDot || localName == "_" {
		return false, nil
	}

	// Walk AST to find runtime.GOOS and runtime.GOARCH selector expressions.
	var replacements []replacement
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != localName {
			return true
		}
		switch sel.Sel.Name {
		case "GOOS":
			if rewriteGOOS {
				start := fset.Position(sel.Pos()).Offset
				end := fset.Position(sel.End()).Offset
				replacements = append(replacements, replacement{start, end, fmt.Sprintf("%q", targetGOOS)})
			}
		case "GOARCH":
			if rewriteGOARCH {
				start := fset.Position(sel.Pos()).Offset
				end := fset.Position(sel.End()).Offset
				replacements = append(replacements, replacement{start, end, fmt.Sprintf("%q", targetGOARCH)})
			}
		}
		return true
	})

	if len(replacements) == 0 {
		return false, nil
	}

	// Apply replacements right-to-left so earlier offsets remain valid.
	sort.Slice(replacements, func(i, j int) bool {
		return replacements[i].start > replacements[j].start
	})
	result := make([]byte, len(src))
	copy(result, src)
	for _, r := range replacements {
		var out []byte
		out = append(out, result[:r.start]...)
		out = append(out, r.literal...)
		out = append(out, result[r.end:]...)
		result = out
	}

	// If the runtime import is no longer used, remove it.
	result = removeUnusedRuntimeImport(result, localName)

	return true, os.WriteFile(path, result, 0o644)
}

// findRuntimeImport scans imports for "runtime" and returns the local name
// used in the file. It handles aliases (import rt "runtime"), blank imports
// (import _ "runtime"), and dot imports (import . "runtime").
func findRuntimeImport(f *ast.File) (localName string, isDotImport bool, hasRuntime bool) {
	for _, imp := range f.Imports {
		if imp.Path.Value != `"runtime"` {
			continue
		}
		hasRuntime = true
		if imp.Name != nil {
			switch imp.Name.Name {
			case ".":
				isDotImport = true
				return
			case "_":
				localName = "_"
				return
			default:
				localName = imp.Name.Name
				return
			}
		}
		localName = "runtime"
		return
	}
	return "", false, false
}

// removeUnusedRuntimeImport re-parses the modified source and removes the
// "runtime" import line if the package name is no longer used as a selector
// prefix anywhere in the file.
func removeUnusedRuntimeImport(src []byte, runtimeLocalName string) []byte {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return src // Can't parse — leave as-is.
	}

	// Check if the runtime local name is still used as a selector prefix.
	stillUsed := false
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if ok && ident.Name == runtimeLocalName {
			stillUsed = true
			return false
		}
		return true
	})
	if stillUsed {
		return src
	}

	return removeImportLine(src, `"runtime"`)
}

// removeImportLine removes an import line from Go source using line-based
// text manipulation. Handles both standalone (import "runtime") and grouped
// (import (\n...\n)) forms. Also removes aliased imports (import rt "runtime").
func removeImportLine(src []byte, importPath string) []byte {
	lines := bytes.Split(src, []byte("\n"))
	var result [][]byte
	inGroupImport := false
	groupStart := -1

	for i, line := range lines {
		trimmed := bytes.TrimSpace(line)

		// Track grouped import blocks.
		if bytes.HasPrefix(trimmed, []byte("import (")) {
			inGroupImport = true
			groupStart = i
			result = append(result, line)
			continue
		}
		if inGroupImport && bytes.Equal(trimmed, []byte(")")) {
			inGroupImport = false
			// If the group is now empty (only "import (" and ")"), remove both.
			if groupStart >= 0 && allBlankBetween(result, groupStart+1) {
				result = result[:groupStart]
				continue // Skip the closing paren too.
			}
			result = append(result, line)
			continue
		}

		// In a group: skip the line with the target import path.
		if inGroupImport && bytes.Contains(trimmed, []byte(importPath)) {
			continue
		}

		// Standalone: import "runtime" or import rt "runtime"
		if !inGroupImport && bytes.HasPrefix(trimmed, []byte("import ")) && bytes.Contains(trimmed, []byte(importPath)) {
			continue
		}

		result = append(result, line)
	}

	return bytes.Join(result, []byte("\n"))
}

// allBlankBetween returns true if all lines in result from index start onward
// are blank (whitespace only). Used to detect empty import groups.
func allBlankBetween(lines [][]byte, start int) bool {
	for i := start; i < len(lines); i++ {
		if len(bytes.TrimSpace(lines[i])) > 0 {
			return false
		}
	}
	return true
}

// patchGuestWazeroCompiler walks the shadow copy looking for wazero's
// internal/platform/platform.go and patches CompilerSupported() and
// CompilerSupports() to always return false. This prevents the guest from
// selecting the compiler engine (which requires mmap, unavailable in WASM).
//
// Detection criteria (all required):
//  1. Filename is "platform.go"
//  2. Path contains "internal/platform/"
//  3. File contains "func CompilerSupported() bool"
func patchGuestWazeroCompiler(dir string, verbose bool) error {
	patched := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Base(path) != "platform.go" {
			return nil
		}
		if !strings.Contains(filepath.ToSlash(path), "internal/platform/") {
			return nil
		}

		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if !bytes.Contains(src, []byte("func CompilerSupported() bool")) {
			return nil
		}

		changed := false

		// Patch CompilerSupported() → return false.
		if newSrc, ok := replaceFuncBody(src, "CompilerSupported"); ok {
			src = newSrc
			changed = true
		}

		// Patch CompilerSupports() → return false (added in wazero v1.6+).
		if newSrc, ok := replaceFuncBody(src, "CompilerSupports"); ok {
			src = newSrc
			changed = true
		}

		if !changed {
			return nil
		}

		// The "experimental" import is only used inside CompilerSupports.
		// After patching the body to "return false", it becomes unused.
		// Use a substring that matches the full import path
		// ("github.com/tetratelabs/wazero/experimental").
		src = removeImportLine(src, `wazero/experimental`)

		if err := os.WriteFile(path, src, info.Mode()); err != nil {
			return fmt.Errorf("writing patched %s: %w", path, err)
		}

		patched++
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: patched CompilerSupported/CompilerSupports in %s\n", path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if verbose && patched == 0 {
		fmt.Fprintf(os.Stderr, "wasmforge: no guest wazero platform.go found (ok if guest doesn't embed wazero)\n")
	}
	return nil
}

// replaceFuncBody finds "func <name>(" in src, locates the matching { },
// and replaces the body with "\treturn false\n". Returns the new source and
// true if a replacement was made.
func replaceFuncBody(src []byte, funcName string) ([]byte, bool) {
	sig := []byte("func " + funcName + "(")
	idx := bytes.Index(src, sig)
	if idx < 0 {
		return src, false
	}

	// Find the opening brace after the signature.
	openBrace := bytes.IndexByte(src[idx:], '{')
	if openBrace < 0 {
		return src, false
	}
	openBrace += idx // absolute offset

	// Brace-count to find the matching close.
	depth := 1
	pos := openBrace + 1
	for pos < len(src) && depth > 0 {
		switch src[pos] {
		case '{':
			depth++
		case '}':
			depth--
		}
		pos++
	}
	if depth != 0 {
		return src, false
	}
	closeBrace := pos - 1 // points at the matching '}'

	// Replace body: everything between { and } exclusive.
	var buf bytes.Buffer
	buf.Write(src[:openBrace+1])
	buf.WriteString("\n\treturn false\n")
	buf.Write(src[closeBrace:])
	return buf.Bytes(), true
}
