<div align="center">

# 🛡️ Hranix Shield

**All your local security tools in one simple panel — without DevOps.**

[English](README.md) · [Русский](README.ru.md)

*Local · Private · Open source (AGPLv3 + CLA)*

</div>

---

**Hranix Shield** is a free, open-source security panel for Windows that brings the power of
enterprise-grade security tools — **CrowdSec, Osquery, ClamAV, Wazuh, restic** — into one
clear, human-readable dashboard running on **your own machine**.

No cloud. No telemetry. Your data never leaves your computer.

## Why Hranix Shield

Tools like CrowdSec or Wazuh are powerful — and hostile to non-specialists. Hranix Shield
doesn't replace them; it **packages** them: install once, understand at first glance.

- 🔥 **Perimeter** — OS firewall state, open ports (per process), firewall rules, one-click
  block/unblock (with a real admin prompt — your rights are never cached).
- 🛰️ **Intrusion detection** — CrowdSec bans and attack attempts on this machine.
- 🦠 **Antivirus** — ClamAV scans (quick / full / custom folder), quarantine with restore,
  scan history.
- 📡 **Network** — live connections table (process, address, country), offline GeoIP world map,
  block IP / terminate process with multi-step confirmation.
- 💾 **Backups** — restic-powered, scheduled (daily 04:00) + manual, integrity check with
  auto-restore on corruption.
- 📋 **OS logs** — Wazuh FIM events with severity, filters, CSV/JSON export.
- 🩺 **System health** — subsystem status, metrics history, de-identified diagnostic report.

**Honesty by design:** if something is not configured, the panel says so and explains how to
fix it — a disabled button always tells you *why*. A fake "all clear" is treated as a bug.

## Install (Windows)

> Windows 10/11 x64, administrator rights. Panel language: RU / EN (switch in the top bar).

1. Download `hranix-shield-setup.exe` from
   [**Releases**](../../releases).
2. Run it and accept the Windows UAC prompt. The app installs to
   `C:\Program Files\Hranix Shield` and starts automatically (tray icon).
3. Open the panel: click the tray icon → **«Открыть панель»**, or open
   <http://127.0.0.1:8080>.

### Create your admin account

The panel has no public registration — the installer creates your admin account for you.
After copying the files, it shows the generated credentials on the final wizard page
(login `admin` + a 20-character random password). **Save the password right away: it is
shown only once.** Change it after your first sign-in.

If you install silently (`/VERYSILENT`, e.g. scripted deployments), there is no wizard
page — the installer writes the same credentials to
`%LOCALAPPDATA%\Hranix\Hranix Shield\admin-credentials.txt` instead.

**Manual way (for advanced users):** the installer never touches an existing admin — if
`%LOCALAPPDATA%\Hranix\Hranix Shield\config.env` already contains a non-empty
`BOOTSTRAP_ADMIN_USERNAME`, your credentials stay as they are (the same applies to
CI/scripts that pre-write the file). To set the account by hand, create the file before
the first launch:

```ini
BOOTSTRAP_ADMIN_USERNAME=your-login
BOOTSTRAP_ADMIN_PASSWORD=your-strong-password
```

Then restart the app (tray → Exit → start again) and log in.

### Out of the box vs. optional stack

| Works immediately | Needs one click (Docker Desktop) |
|---|---|
| Firewall, open ports, firewall rules | Intrusion detection (CrowdSec) |
| Network connections, GeoIP map | Antivirus scans (ClamAV) |
| OS processes telemetry | OS logs / FIM (Wazuh) |
| Backups (restic is bundled) | |

To enable the second column: install [Docker Desktop](https://www.docker.com/products/docker-desktop/),
then in the panel open **Settings → Security stack → Deploy**. The app generates configs and
secrets, starts the tools, and wires the credentials itself — then asks to restart the app.

## Docker Compose (advanced)

```bash
docker compose up -d                          # the panel (127.0.0.1:8080)
docker compose -f infra/security/crowdsec/docker-compose.yml up -d
docker compose -f infra/security/clamav/docker-compose.yml  up -d
docker compose -f infra/security/wazuh/docker-compose.yml   up -d
```

Note: in Docker mode the *Perimeter* and *Network* consoles see the container, not your
host — use the native installer for full functionality.

## Build from source

```bash
git clone https://github.com/hranix-shield/hranix-shield.git
cd hranix-shield
python -m venv .venv && .venv/Scripts/pip install -r server/requirements-packaged.txt
cd server && ../.venv/Scripts/python -m pytest -q     # unit tests, fully offline
```

Release artifacts for Windows are built by `.github/workflows/windows-build.yml`.
macOS (`.app`/`.dmg`) and Linux (`.deb` + systemd) packaging lives in `packaging/`.

## Privacy

- The panel binds to **127.0.0.1** only.
- **Zero telemetry.** The only "report" is a de-identified diagnostic bundle you explicitly
  save locally.
- Backups are encrypted (restic); secrets live in your user profile, never in the cloud.

## License

- Code: **AGPLv3** — see [LICENSE](LICENSE); contributions are accepted under
  [CLA](CLA.md).
- Third-party components: Osquery (Apache-2.0), restic (BSD-2), CrowdSec (MIT) are bundled;
  Wazuh and ClamAV (GPLv2) run as **separate containers/services** and are never linked into
  this codebase.
- Models/tools with non-free licenses (Picovoice, openWakeWord pre-trained models) are not
  used at all.

## Contributing

Bug reports and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md)
and [SECURITY.md](SECURITY.md) for responsible disclosure.
