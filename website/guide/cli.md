# CLI & Service

meow-rs is a single binary. Day to day you run it with a config path; for unattended
operation you install it as a system service.

## Command-line flags

```bash
meow [OPTIONS] [COMMAND]
```

| Flag | Description |
| --- | --- |
| `-f, --config <PATH>` | Config file path (default `config.yaml`) |
| `-d, --directory <DIR>` | Home directory for resource discovery (geodata, caches); relative config paths resolve under it |
| `-t, --test` | Validate the config and exit without starting |

```bash
# build, validate, run
cargo build --release
./target/release/meow -f config.yaml -t      # pre-flight check
./target/release/meow -f config.yaml         # run
```

### Logging

The console log level comes from `RUST_LOG` (default `info`); the config's `log-level`
sets the default too. The WebSocket `/logs` stream always carries full detail and is
filtered client-side via `?level=`.

## Run as a service

Subcommands install meow-rs as a managed service (systemd on Linux, launchd on macOS,
Windows Service on Windows). These need root/sudo (or an elevated shell on Windows).

| Command | Action |
| --- | --- |
| `meow install -f <PATH>` | Install and start the service |
| `meow uninstall` | Stop and remove the service |
| `meow status` | Show service status |

### Linux (systemd)

```bash
sudo ./meow install -f /etc/meow/config.yaml
```

Writes `/etc/systemd/system/meow.service`, then reloads, enables, and starts it. The
service runs as root (required so the transparent-proxy firewall rules can be installed),
with the config path baked into the unit.

### macOS (launchd)

```bash
sudo ./meow install -f /path/to/config.yaml
```

Copies the config under `~/Library/Application Support/meow/`, writes
`~/Library/LaunchAgents/com.meow.proxy.plist`, and bootstraps it. Runs as your user (the
pf rules use a UID bypass for loop avoidance). Logs go to `~/Library/Logs/meow/`.

### Windows (Service Control Manager)

```powershell
# From an elevated prompt, with wintun.dll next to meow.exe
.\meow.exe install -f C:\meow\config.yaml
```

Installs the `meow` service (LocalSystem). Wintun TUN / `tun:` needs that elevation.
Official Windows zips ship `wintun.dll` beside the executable; if it is missing
the official DLL embedded in `meow.exe` is extracted on first TUN start.

## Hot reload

You don't have to restart to apply config changes. The REST API can reload the whole file
in place:

```bash
curl -X PUT 'http://127.0.0.1:9090/configs' \
  -H 'Authorization: Bearer <secret>' \
  -d '{"path":"/etc/meow/config.yaml"}'
```

See [`PUT /configs`](../reference/rest-api#config) for the payload options and the
`?force=true` flag.
