// gen-build-assets generates internal/build/build_assets.tar.gz containing
// all runtime build assets needed by GenerateHost when no local source tree
// is available (distribution mode).
//
// Archive contents:
//
//	wazero/    - wazero fork source (filtered: only *.go, *.s, go.mod, go.sum)
//	hostmod/   - internal/hostmod source
//	runtime/   - internal/runtime source
//	names/     - internal/names source
//	go.sum     - wasmforge go.sum for dependency verification
//
// Run from the wasmforge module root:
//
//	go run ./cmd/gen-build-assets
package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	var wazeroDir string
	var outputPath string

	flag.StringVar(&wazeroDir, "wazero-dir", "", "path to wazero fork (defaults to ./wazero relative to module root)")
	flag.StringVar(&outputPath, "output", "", "output path (defaults to internal/build/build_assets.tar.gz)")
	flag.Parse()

	moduleRoot, err := findModuleRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-build-assets: %v\n", err)
		os.Exit(1)
	}

	if wazeroDir == "" {
		wazeroDir = filepath.Join(moduleRoot, "wazero")
	}
	wazeroDir, err = filepath.Abs(wazeroDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-build-assets: resolving wazero dir: %v\n", err)
		os.Exit(1)
	}

	if outputPath == "" {
		outputPath = filepath.Join(moduleRoot, "internal", "build", "build_assets.tar.gz")
	}

	fileCount, err := generateArchive(moduleRoot, wazeroDir, outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-build-assets: %v\n", err)
		os.Exit(1)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-build-assets: stat output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("gen-build-assets: wrote %d files, %.1f KB → %s\n",
		fileCount, float64(info.Size())/1024, outputPath)
}

// generateArchive builds the tar.gz archive and returns the number of files written.
func generateArchive(moduleRoot, wazeroDir, outputPath string) (int, error) {
	f, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("creating output: %w", err)
	}
	defer f.Close()

	gw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return 0, fmt.Errorf("creating gzip writer: %w", err)
	}
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	var totalFiles int

	// Add wazero fork (filtered).
	n, err := addWazeroDir(tw, wazeroDir)
	if err != nil {
		return 0, fmt.Errorf("adding wazero: %w", err)
	}
	totalFiles += n

	// Add internal packages.
	pkgs := []struct {
		src    string
		prefix string
	}{
		{filepath.Join(moduleRoot, "internal", "hostmod"), "hostmod"},
		{filepath.Join(moduleRoot, "internal", "runtime"), "runtime"},
		{filepath.Join(moduleRoot, "internal", "names"), "names"},
	}
	for _, pkg := range pkgs {
		n, err := addDir(tw, pkg.src, pkg.prefix, isSourceFile)
		if err != nil {
			return 0, fmt.Errorf("adding %s: %w", pkg.prefix, err)
		}
		totalFiles += n
	}

	// Add sysshim tree (recursive — has subdirs and per-subdir go.mod files).
	// Needed at runtime when a guest depends on golang.org/x/sys and the
	// wasmforge module source isn't otherwise locatable on disk.
	n, err = addSysshimDir(tw, filepath.Join(moduleRoot, "internal", "sysshim"))
	if err != nil {
		return 0, fmt.Errorf("adding sysshim: %w", err)
	}
	totalFiles += n

	// Add go.sum.
	gosumPath := filepath.Join(moduleRoot, "go.sum")
	if err := addFile(tw, gosumPath, "go.sum"); err != nil {
		return 0, fmt.Errorf("adding go.sum: %w", err)
	}
	totalFiles++

	return totalFiles, nil
}

// addSysshimDir adds the internal/sysshim tree under the "sysshim/" prefix.
// Walks recursively because sysshim has nested subdirs (unix, purego,
// windows, windows/svc, etc.) and per-subdir go.mod files that the
// injection step needs at runtime. Includes *.go, *.s, and go.mod; excludes
// _test.go.
func addSysshimDir(tw *tar.Writer, sysshimDir string) (int, error) {
	count := 0
	err := filepath.Walk(sysshimDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		name := info.Name()
		if name != "go.mod" && !isSourceFile(name) {
			return nil
		}
		rel, err := filepath.Rel(sysshimDir, path)
		if err != nil {
			return err
		}
		archivePath := filepath.ToSlash(filepath.Join("sysshim", rel))
		if err := addFile(tw, path, archivePath); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}

// addWazeroDir adds the wazero fork to the archive under the "wazero/" prefix.
// It applies the wazero-specific skip list and only includes *.go, *.s, go.mod, go.sum files.
func addWazeroDir(tw *tar.Writer, wazeroDir string) (int, error) {
	count := 0
	err := filepath.Walk(wazeroDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(wazeroDir, path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			if shouldSkipWazeroDir(rel) {
				return filepath.SkipDir
			}
			return nil
		}

		if !isWazeroFile(info.Name()) {
			return nil
		}

		// Skip test files in wazero.
		if strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		archivePath := filepath.ToSlash(filepath.Join("wazero", rel))
		if err := addFile(tw, path, archivePath); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}

// shouldSkipWazeroDir reports whether a wazero directory should be skipped entirely.
func shouldSkipWazeroDir(rel string) bool {
	if rel == "." {
		return false
	}
	// Get the top-level directory name.
	top := rel
	if idx := strings.IndexRune(rel, filepath.Separator); idx >= 0 {
		top = rel[:idx]
	}
	switch top {
	case ".git", "vendor", "cmd", "examples", "site", ".github", ".netlify", "testdata":
		return true
	}
	return false
}

// isWazeroFile reports whether a filename should be included from the wazero fork.
func isWazeroFile(name string) bool {
	return name == "go.mod" || name == "go.sum" || strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".s")
}

// isSourceFile reports whether a filename is a non-test Go source or assembly file.
func isSourceFile(name string) bool {
	if strings.HasSuffix(name, "_test.go") {
		return false
	}
	return strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".s")
}

// addDir adds non-test Go source files directly in srcDir to the archive under archivePrefix/.
func addDir(tw *tar.Writer, srcDir, archivePrefix string, include func(name string) bool) (int, error) {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", srcDir, err)
	}

	count := 0
	for _, e := range entries {
		if e.IsDir() || !include(e.Name()) {
			continue
		}
		srcPath := filepath.Join(srcDir, e.Name())
		archivePath := archivePrefix + "/" + e.Name()
		if err := addFile(tw, srcPath, archivePath); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// addFile reads srcPath and writes it to the archive at archivePath.
func addFile(tw *tar.Writer, srcPath, archivePath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", srcPath, err)
	}

	hdr := &tar.Header{
		Name:     archivePath,
		Mode:     0o644,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
		ModTime:  time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("writing tar header for %s: %w", archivePath, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("writing tar body for %s: %w", archivePath, err)
	}
	return nil
}

// findModuleRoot walks up from the current directory looking for the wasmforge go.mod.
func findModuleRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting cwd: %w", err)
	}

	const modPath = "github.com/praetorian-inc/wasmforge"
	dir := cwd
	for dir != "/" && dir != "." {
		data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && strings.Contains(string(data), modPath) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached filesystem root (e.g., C:\ on Windows)
		}
		dir = parent
	}
	return "", fmt.Errorf("cannot find wasmforge module root (go.mod with %s) from %s", modPath, cwd)
}
