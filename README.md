# netplus

`netplus` is a small, portable proxy-routing client built with Rust and Tokio. It
provides a local SOCKS5 endpoint and routes each TCP connection directly, through
an upstream SOCKS5 proxy, or blocks it according to ordered domain and CIDR rules.

This is the user-space foundation of a Netch-like tool. Process interception,
TUN routing, UDP relay, and additional proxy protocols require separate
platform-specific transports and are not part of this first version.

## Run

```sh
cp netplus.example.yaml config
cargo run --release
```

Point an application at `socks5://127.0.0.1:1080`. Set `RUST_LOG=debug` for
per-connection routing and byte-count logs.

### Windows process mode

Run an Administrator terminal and add process selectors:

```yaml
process_mode:
  executable_names: [game.exe, launcher.exe]
  process_ids: [1234]
  bypass_private: true
```

Process mode uses WinDivert to identify socket operations by PID and redirect
matching IPv4 TCP connections into an internal transparent listener. The
selected application does not need to support or configure a proxy. WinDivert
loads its signed driver on demand. Place the 64-bit official
`WinDivert.dll` and `WinDivert64.sys` files beside `netplus.exe`.
Executable names are case-insensitive and must include the extension.
WinDivert is distributed under LGPL-3.0-or-later; retain its license file with
distributed Windows packages.

For local compatibility testing, `process_mode.backend: netch` dynamically loads
Netch's redirector runtime instead. Put user-supplied `Redirector.bin`,
`nfapi.dll`, and `nfdriver.sys` files in a `netch` directory beside `config`.
This experimental backend supports TCP/UDP and IPv4/IPv6, talks directly to the
configured upstream SOCKS5 server, and accepts executable-name selectors only.
It does not apply netplus routing rules to intercepted traffic. The NetFilter
runtime is third-party software and is not distributed by netplus.
Use `netplus.netch.example.yaml` as the local test profile. The standard Windows
package continues to use WinDivert unless a Netch runtime is explicitly supplied
to the packaging script.
Start from `netplus.windows.example.yaml`. Because interception happens after
Windows resolves DNS, process-mode routing uses CIDR rules; domain rules still
apply to clients using the local SOCKS5 endpoint.

For Windows builds, download the official WinDivert SDK and point Cargo at its
`x64` directory:

```powershell
$env:WINDIVERT_PATH = "C:\path\to\WinDivert-2.2.2-A\x64"
cargo build --release
```

To create a ready-to-run directory containing the executable, DLL, driver, and
example configuration:

```powershell
.\scripts\build-windows.ps1 -WinDivertPath C:\path\to\WinDivert-2.2.2-A\x64
```

Add `-NetchRuntimePath C:\path\to\netch-runtime` to copy locally supplied test
runtime files into the package.

To remove the local test driver, close Netch and netplus, then right-click
`uninstall-netfilter2.bat` and run it as Administrator. If Windows still has the
driver open, restart Windows and run the script again.

### Desktop GUI

The Windows package includes `netplus-gui.exe`, a native desktop interface for
managing the proxy server, intercepted applications, ordered routing rules,
connection activity, and live logs. Advanced users can still edit the raw YAML
profile. Run the GUI as Administrator so its `netplus.exe` child can load
WinDivert.

The GUI always loads and saves `config` beside the executables. There is no
profile picker; use the structured settings pages or the Advanced YAML page.
If `config` does not exist, the GUI or CLI creates a minimal valid profile
automatically without showing a missing-file error.
Clicking **Start** saves the current GUI settings to `config` before launching
the listener.
On Windows, the GUI requests Administrator privileges through UAC when it
starts. If elevation is declined, the interface remains available but process
interception stays disabled.

```powershell
Start-Process .\netplus-gui.exe -Verb RunAs
```

## Configuration

```yaml
listen: 127.0.0.1:1080
log_level: info
upstream: socks5://user:password@proxy.example:1080

routing:
  default: proxy
  rules:
    - action: direct
      domains: [localhost, "*.lan"]
      cidrs: [127.0.0.0/8, 10.0.0.0/8]
    - action: block
      domains: [ads.example]
```

Rules are evaluated from top to bottom. A domain rule matches the named domain
and all its subdomains. CIDR rules apply when the SOCKS client supplies an IP
address. Supported actions are `direct`, `proxy`, and `block`. The local endpoint
accepts unauthenticated SOCKS5 `CONNECT` requests; the upstream supports optional
username/password authentication.

`log_level` accepts `trace`, `debug`, `info`, `warn`, or `error`. If `RUST_LOG`
is set, it overrides the YAML value.

Verify SOCKS5 connectivity, authentication, and the upstream `CONNECT` command:

```sh
netplus --test-upstream
```

The check connects through the upstream to `ifconfig.me`, requests `/ip`, and
prints the public IP seen through the proxy. If that service rejects the
upstream, netplus automatically tries independent public-IP services. The
desktop GUI exposes the same check under **Proxy Server → Test connection**.

## Scope

- TCP SOCKS5 ingress
- Direct and upstream SOCKS5 egress
- IPv4, IPv6, and domain targets
- Ordered domain/CIDR routing
- Concurrent Tokio connection relay
- Graceful Ctrl-C shutdown
- Windows IPv4 TCP interception by executable name or PID

Process interception currently supports IPv4 TCP. IPv6 and UDP traffic are left
untouched.

`bypass_private` prevents interception of localhost, LAN, link-local, and
carrier-grade NAT destinations. Keep it enabled for games and launchers that
use local helper processes.

The project is licensed under GPL-3.0-or-later.
