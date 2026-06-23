// Package build orchestrates the wasmforge build pipeline.
package build

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/wasmforge/internal/patch"
)

const version = "0.1.0"

// PatchedGOROOT prepares a patched GOROOT with networking-enabled stdlib.
// Uses a cache keyed on Go version + wasmforge version + patch options.
// Returns the path to the patched GOROOT.
func PatchedGOROOT(verbose bool, win32APIs bool) (string, error) {
	goroot, err := detectGOROOT()
	if err != nil {
		return "", err
	}

	goVersion, err := detectGoVersion()
	if err != nil {
		return "", err
	}

	patchKey, err := patch.Fingerprint(patch.PatchOptions{Win32APIs: win32APIs})
	if err != nil {
		return "", fmt.Errorf("computing patch fingerprint: %w", err)
	}

	cacheDir, err := cacheDir(goVersion, win32APIs, patchKey)
	if err != nil {
		return "", err
	}

	// Check if already cached.
	markerFile := filepath.Join(cacheDir, ".wasmforge-patched")
	if _, err := os.Stat(markerFile); err == nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: using cached patched GOROOT at %s\n", cacheDir)
		}
		return cacheDir, nil
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: preparing patched GOROOT from %s\n", goroot)
	}

	// Clean and recreate.
	os.RemoveAll(cacheDir)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("creating cache dir: %w", err)
	}

	// Strategy: symlink bin/, pkg/, lib/ from real GOROOT.
	// Copy only src/syscall/ and src/net/ subtrees fully.
	// Symlink rest of src/.

	gorootSrc := filepath.Join(goroot, "src")
	cachedSrc := filepath.Join(cacheDir, "src")

	// Symlink top-level dirs.
	for _, dir := range []string{"bin", "pkg", "lib"} {
		src := filepath.Join(goroot, dir)
		dst := filepath.Join(cacheDir, dir)
		if _, err := os.Stat(src); err == nil {
			if err := os.Symlink(src, dst); err != nil {
				return "", fmt.Errorf("symlinking %s: %w", dir, err)
			}
		}
	}

	// Symlink go.env if present.
	goenv := filepath.Join(goroot, "go.env")
	if _, err := os.Stat(goenv); err == nil {
		os.Symlink(goenv, filepath.Join(cacheDir, "go.env"))
	}

	// Create src/ directory.
	if err := os.MkdirAll(cachedSrc, 0o755); err != nil {
		return "", fmt.Errorf("creating src dir: %w", err)
	}

	// Get list of src/ subdirectories.
	entries, err := os.ReadDir(gorootSrc)
	if err != nil {
		return "", fmt.Errorf("reading GOROOT/src: %w", err)
	}

	// Directories we need to copy (not symlink) for patching.
	copyDirs := map[string]bool{
		"syscall": true,
		"net":     true,
		"os":      true,
	}

	for _, entry := range entries {
		name := entry.Name()
		src := filepath.Join(gorootSrc, name)
		dst := filepath.Join(cachedSrc, name)

		if copyDirs[name] {
			// Deep copy this directory.
			if err := copyDir(src, dst); err != nil {
				return "", fmt.Errorf("copying %s: %w", name, err)
			}
		} else {
			// Symlink.
			if err := os.Symlink(src, dst); err != nil {
				return "", fmt.Errorf("symlinking src/%s: %w", name, err)
			}
		}
	}

	// Apply patches.
	if err := patch.Apply(cachedSrc, patch.PatchOptions{Win32APIs: win32APIs}); err != nil {
		return "", fmt.Errorf("applying patches: %w", err)
	}

	// Write marker.
	if err := os.WriteFile(markerFile, []byte(version+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("writing marker: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: patched GOROOT ready at %s\n", cacheDir)
	}
	return cacheDir, nil
}

// CleanCache removes the patched GOROOT cache.
func CleanCache() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cacheBase := filepath.Join(home, ".wasmforge", "cache")
	return os.RemoveAll(cacheBase)
}

func detectGOROOT() (string, error) {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return "", fmt.Errorf("detecting GOROOT: %w", err)
	}
	goroot := strings.TrimSpace(string(out))
	if goroot == "" {
		return "", fmt.Errorf("GOROOT is empty")
	}
	return goroot, nil
}

func detectGoVersion() (string, error) {
	out, err := exec.Command("go", "version").Output()
	if err != nil {
		return "", fmt.Errorf("detecting Go version: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func cacheDir(goVersion string, win32APIs bool, patchKey string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home dir: %w", err)
	}

	win32Flag := "0"
	if win32APIs {
		win32Flag = "1"
	}
	hash := sha256.Sum256([]byte(goVersion + "|" + version + "|win32=" + win32Flag + "|patch=" + patchKey))
	key := fmt.Sprintf("%x", hash[:8])

	return filepath.Join(home, ".wasmforge", "cache", key), nil
}

// randomizeGOROOTNetFunctions creates a per-build overlay of the patched GOROOT
// with renamed internal net functions. This prevents YARA rules from matching
// gopclntab entries like "net.interfaceAddrTable" which appear in every build.
//
// Approach: create a temp GOROOT that symlinks everything to the cached GOROOT
// except src/net/ which gets a deep copy with per-build random function names.
// The renamed functions are unexported and internal to the net package, so
// renaming within the package is safe.
func randomizeGOROOTNetFunctions(cachedGOROOT, tmpDir string, verbose bool) (string, error) {
	wl := newWordList()
	used := make(map[string]bool)

	// Generate per-build replacement names for internal net functions.
	replacements := [][2]string{
		{"interfaceAddrTable", wl.generate(used)},
		{"interfaceMulticastAddrTable", wl.generate(used)},
		{"interfaceTable", wl.generate(used)},
	}

	// Create overlay GOROOT dir.
	overlayGOROOT := filepath.Join(tmpDir, "goroot-overlay")
	if err := os.MkdirAll(overlayGOROOT, 0o755); err != nil {
		return "", fmt.Errorf("creating overlay GOROOT: %w", err)
	}

	// Symlink top-level dirs (bin, pkg, lib, go.env) to cached GOROOT.
	for _, name := range []string{"bin", "pkg", "lib"} {
		src := filepath.Join(cachedGOROOT, name)
		dst := filepath.Join(overlayGOROOT, name)
		if _, err := os.Stat(src); err == nil {
			if err := os.Symlink(src, dst); err != nil {
				return "", fmt.Errorf("symlinking %s: %w", name, err)
			}
		}
	}
	goenv := filepath.Join(cachedGOROOT, "go.env")
	if _, err := os.Stat(goenv); err == nil {
		os.Symlink(goenv, filepath.Join(overlayGOROOT, "go.env"))
	}

	// Create src/ directory.
	overlaySrc := filepath.Join(overlayGOROOT, "src")
	if err := os.MkdirAll(overlaySrc, 0o755); err != nil {
		return "", fmt.Errorf("creating overlay src: %w", err)
	}

	// Symlink all src/ subdirs to cached GOROOT except "net".
	cachedSrc := filepath.Join(cachedGOROOT, "src")
	entries, err := os.ReadDir(cachedSrc)
	if err != nil {
		return "", fmt.Errorf("reading cached src: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		src := filepath.Join(cachedSrc, name)
		dst := filepath.Join(overlaySrc, name)
		if name == "net" {
			// Deep copy src/net/ for per-build modification.
			if err := copyDir(src, dst); err != nil {
				return "", fmt.Errorf("copying src/net: %w", err)
			}
		} else {
			// Symlink: if the cached entry is itself a symlink, resolve it
			// to avoid broken symlink chains.
			target, err := filepath.EvalSymlinks(src)
			if err != nil {
				target = src
			}
			if err := os.Symlink(target, dst); err != nil {
				return "", fmt.Errorf("symlinking src/%s: %w", name, err)
			}
		}
	}

	// Apply per-build renames to the copied src/net/ files.
	netDir := filepath.Join(overlaySrc, "net")
	goFiles, _ := filepath.Glob(filepath.Join(netDir, "*.go"))
	renamed := 0
	for _, f := range goFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(data)
		modified := false
		for _, pair := range replacements {
			if strings.Contains(content, pair[0]) {
				content = strings.ReplaceAll(content, pair[0], pair[1])
				modified = true
			}
		}
		if modified {
			if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
				return "", fmt.Errorf("writing %s: %w", f, err)
			}
			renamed++
		}
	}

	if verbose && renamed > 0 {
		fmt.Fprintf(os.Stderr, "wasmforge: randomized %d net function names in GOROOT overlay\n", renamed)
	}

	return overlayGOROOT, nil
}

// copyDir recursively copies a directory.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			// Always create writable dirs (source may be read-only module cache).
			return os.MkdirAll(dstPath, 0o755)
		}

		// Copy regular file with writable permissions.
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dstPath, data, 0o644)
	})
}
