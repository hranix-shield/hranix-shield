; A-21: Inno Setup script building the Hranix Shield Windows installer.
;
; Wraps the PyInstaller onedir bundle produced by `hranix-shield.spec`
; (`packaging/windows/dist/Hranix Shield/*`, built by
; `.github/workflows/windows-build.yml` on a `windows-latest` runner — see
; that file and `packaging/windows/README.md` for why this cannot be
; built/compiled locally in this session: no Windows machine, and Inno
; Setup's own compiler (`ISCC.exe`) only runs on Windows).
;
; Installs into Program Files (`{autopf}` — requires admin rights to
; INSTALL, same as any standard Windows installer targeting a
; machine-wide location; the installed, RUNNING app itself never asks for
; elevation afterwards — see server/launcher.py and
; hranix_shield_tray.py, both of which run as the logged-in user with no
; privilege escalation, same principle as macOS/Linux's own installers and
; CLAUDE.md's "не поднимать привилегии огулом").
;
; Not signed (no Authenticode certificate) — same explicitly-out-of-scope
; decision already made for macOS (no notarization) and Linux (no
; GPG-signed .deb repo); Windows SmartScreen will show an "unrecognized
; app" warning on first run of the installer, comparable friction to
; Gatekeeper's "unknown developer" prompt on macOS — documented honestly
; in README.md, not hidden.

#define MyAppName "Hranix Shield"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Hranix"
#define MyAppExeName "Hranix Shield.exe"

[Setup]
; Fixed, random-once AppId (a GUID, NOT the app name) — Inno Setup's own
; documented way to let upgrade installs recognize "this is the same
; product" across versions regardless of AppName/version changes. Generated
; once for this task (via Python's uuid.uuid4(), not reused from anywhere
; else) — stays constant for every future Hranix Shield Windows release.
AppId={{9F3E7B7A-6C1D-4B4E-9C2A-2B7F6E5D9A31}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://hranix.io
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Installing into Program Files legitimately needs admin rights (see this
; file's header comment) — the same "installer, not the running app,
; asks for elevation" principle already documented for the other two OS
; installers.
PrivilegesRequired=admin
; windows-latest GitHub Actions runners are x64 — PyInstaller therefore
; builds an x64 binary (not verified independently in this session, see
; README.md's honesty section; this is PyInstaller's own default
; behaviour building on an x64 Python interpreter, which
; windows-build.yml's `actions/setup-python` installs). `x64compatible`
; (Inno Setup 6.1+) covers both native x64 and ARM64-with-x64-emulation
; Windows installs, the modern replacement for the older bare `x64` token.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=dist\installer
OutputBaseFilename=hranix-shield-setup
Compression=lzma2
SolidCompression=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
; Russian .isl ships with every Inno Setup install by default
; (compiler:Languages\Russian.isl) — included since CLAUDE.md's
; localization rule is specifically an API-first contract (the SERVER
; never returns localized text, the client/panel localizes). The
; installer is a client-side-only surface with no server involved at all,
; so localizing Inno's own wizard chrome is a low-cost, in-spirit nod to
; the product's RU/EN scope without touching that API rule at all.
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[CustomMessages]
english.StartupTaskDescription=Start Hranix Shield when I sign in to Windows
russian.StartupTaskDescription=Запускать Hranix Shield при входе в Windows

[Tasks]
; Optional, unchecked by default (task brief: "не обязателен намертво, но
; должен быть предложен") — a plain checkbox on the wizard's "additional
; tasks" page, using Inno's built-in {cm:AdditionalIcons} group label
; (already provided by both .isl files above, no custom message needed
; for that one). Left unchecked under a silent/very-silent install (see
; windows-build.yml's smoke test) — /VERYSILENT does not imply "select
; every optional task", it keeps each Task's own default checked state,
; which is exactly the safe, unsurprising behaviour a CI install should
; get: no autostart shortcut is created unless a human wizard user
; actively ticks the box.
Name: "startupicon"; Description: "{cm:StartupTaskDescription}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Source is relative to THIS .iss file's own directory (Inno Setup's
; default SourceDir, unless overridden — not the compiler's invocation
; cwd), i.e. packaging/windows/dist/Hranix Shield/* — matching the
; --distpath packaging/windows/dist the workflow's PyInstaller invocation
; uses (same convention already established by the macOS/Linux specs'
; own README-documented build commands).
Source: "dist\Hranix Shield\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
; {cm:UninstallProgram,%1} is one of Inno Setup's own built-in messages
; ("Uninstall %1"), already provided by both Default.isl and
; Russian.isl above — not a custom string, so it is localized for free,
; same reasoning as {cm:AdditionalIcons}/{cm:LaunchProgram} elsewhere in
; this script.
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
; {userstartup} resolves to the current user's own Startup folder
; (shell:startup, i.e. `%APPDATA%\Microsoft\Windows\Start
; Menu\Programs\Startup`) — a per-user, no-admin-needed autostart
; mechanism, exactly what the task brief asks for ("Inno Setup умеет
; писать туда через [Icons] с {userstartup} constant"). Only created when
; the "startupicon" task above is actually selected.
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startupicon

[Run]
; skipifsilent: deliberately NOT auto-launched during the CI smoke test's
; /VERYSILENT install (see windows-build.yml) — the workflow starts
; the installed .exe itself as its own separate, trackable step (so it
; can poll /health and later terminate the process cleanly), rather than
; racing an installer-spawned child process it does not directly hold a
; handle to. A human running the wizard interactively still gets the
; normal "Launch Hranix Shield now?" checkbox via {cm:LaunchProgram,%1},
; Inno's own built-in message (already covered by both .isl files above).
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

; No [UninstallDelete] entry for the platformdirs data directory
; (%LOCALAPPDATA%\Hranix\Hranix Shield — database, secrets, ClamAV
; quarantine, restic repo; verified against platformdirs==4.10.0's own
; windows.py source, 2026-07-18 — user_data_dir()'s default roaming=False
; resolves to CSIDL_LOCAL_APPDATA, not the roaming %APPDATA%) — same
; "never silently destroy user data on uninstall"
; principle already applied on Linux (packaging/linux/debian/postrm's
; `purge` step deliberately does not remove /var/lib/hranix-shield
; either). Inno's default uninstaller only removes what [Files] installed
; under {app} (Program Files), never touching per-user AppData at all, so
; this is the default behaviour here, not something this script has to
; opt into.
