package build

import (
	"fmt"
	"os"
	"sync"
)

var (
	cachedAssetDirOnce sync.Once
	cachedAssetDir     string
	cachedAssetDirErr  error
)

// ensureAssetsExtracted returns a process-lifetime temp directory containing
// the extracted contents of the embedded build_assets bundle. The first call
// performs the extraction; subsequent calls return the cached path.
//
// The directory is not cleaned up — it lives under the OS temp directory
// (e.g. /tmp on Linux, /var/folders/... on macOS) where the OS reclaims it
// eventually. This avoids re-extracting on every sysshim injection and lets
// the directory survive across multiple build pipeline stages within a
// single wasmforge invocation.
//
// Callers should access well-known subtrees via their bundled prefixes:
// "hostmod", "runtime", "names", "wazero", "sysshim", and "go.sum".
func ensureAssetsExtracted() (string, error) {
	cachedAssetDirOnce.Do(func() {
		dir, err := os.MkdirTemp("", "wasmforge-assets-*")
		if err != nil {
			cachedAssetDirErr = fmt.Errorf("creating asset cache dir: %w", err)
			return
		}
		if err := extractBuildAssets(dir); err != nil {
			os.RemoveAll(dir)
			cachedAssetDirErr = fmt.Errorf("extracting build assets: %w", err)
			return
		}
		cachedAssetDir = dir
	})
	return cachedAssetDir, cachedAssetDirErr
}
