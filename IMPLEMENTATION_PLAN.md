# SAMP – USB Access Manager: Implementation Plan

## 1. Goal

A Windows desktop application (.NET) that:

1. Blocks USB storage devices by default and lets an authorised user **unblock** them.
2. **Automatically re-blocks after 2 hours** from the moment of unblock, even if the UI is closed, the user logs off, or the machine reboots.
3. Manages users **entirely locally** (no cloud/AD dependency), stored in an **encrypted SQLite database** (SQLCipher).

## 2. Key Decisions

| Area | Decision | Reason |
|---|---|---|
| Runtime | .NET 8 (LTS), C# | Current LTS, good Windows service + WPF support |
| UI | WPF (MVVM, CommunityToolkit.Mvvm) | Mature, native Windows, easy tray icon |
| Enforcement | **Windows Service** running as LocalSystem (`SAMP.Service`) | Changing USB policy needs admin; the 2h timer must survive UI exit/logoff/reboot; standard users can't kill it |
| UI ↔ Service | Named pipe IPC with ACL + per-request auth token | UI runs unelevated; service is the only privileged component |
| DB | SQLite + **SQLCipher** (`Microsoft.Data.Sqlite.Core` + `SQLitePCLRaw.bundle_e_sqlcipher`) | AES-256 full-file encryption |
| DB key | Random 256-bit key, protected with **DPAPI (LocalMachine scope)** and stored beside the DB; plus optional offline recovery key | No hard-coded key; service and UI both can open it only on this machine |
| Password hashing | **Argon2id** (`Konscious.Security.Cryptography`) w/ per-user salt, constant-time compare | Resists offline cracking even if DB key leaks |
| Installer | WiX v4 MSI (installs service, sets ACLs, creates shortcuts) | Needs admin once; clean uninstall |

## 3. USB Blocking Mechanism

Primary (storage class), applied by the service:

- Registry `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR` → `Start` = `4` (blocked) / `3` (allowed).
- Optional hardening: `HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}` → `Deny_Read/Deny_Write` (policy-level, takes effect for new mounts without reboot).
- Optional read-only mode: `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect=1`.

Selectable strategies behind an `IUsbBlocker` interface so we can choose after a spike:

1. **Registry/policy (default)** – simple, global.
2. **PnP disable/enable** via SetupAPI/`pnputil /disable-device` for specific devices (VID/PID / instance ID) – enables per-device allow-lists.

Already-mounted drives: on block, enumerate removable volumes (WMI `Win32_DiskDrive` where `InterfaceType='USB'`) and disable/eject them so block is immediate.

Scope note: keyboards/mice (HID) are **not** blocked; only mass storage (configurable device class list later: MTP/phones, etc.).

> **Spike first (Phase 0):** verify on Win10 22H2 and Win11 that the registry+policy combo blocks without reboot; fall back to PnP disable if not.

## 4. The 2-Hour Auto-Block (Core Requirement)

Design so it cannot be bypassed by closing the app or rebooting:

- On unblock, the service writes to DB: `UnblockSession { Id, UserId, UnblockedAtUtc, ExpiresAtUtc = +2h, BootId/MonotonicTicks }`.
- Service holds an in-memory timer for `ExpiresAtUtc`, **and** a 30-second watchdog tick that checks `now >= ExpiresAtUtc` (guards against sleep/hibernate where timers drift).
- **On service start / resume from sleep (`PowerModeChanged`)**: reconcile – if an active session exists and expired → block immediately; if not expired → re-arm timer for remaining time.
- **Fail-secure**: default state on any error, missing record, or DB corruption is **blocked**.
- **Clock tamper defence**: also record `Stopwatch`/uptime-based elapsed time; if system clock jumps backwards, use the longer of wall-clock and monotonic elapsed. Log tamper event.
- **Drift correction**: the watchdog also re-asserts the registry/policy state; if someone manually flips USBSTOR to 3 with no active session, service re-blocks and audits it.
- UI shows countdown, warning toast at 10 min and 1 min; user may **re-block early** anytime. Extending requires an explicit new unblock (re-auth) – no silent extension. (Policy flag: `MaxExtensions`, default 0.)
- Duration is a config constant (120 min) stored in service config, changeable only by Admin.

## 5. Local User Management

Roles: **Admin** (manage users, view all audit, change settings) and **Operator** (unblock/block for self, view own history). Optional **Viewer**.

- First run: setup wizard (requires Windows admin elevation) creates the first Admin; DB + key are created here.
- Fields: Id, Username (unique, case-insens.), DisplayName, Role, PasswordHash, Salt, Argon2 params, IsActive, MustChangePassword, FailedAttempts, LockedUntilUtc, CreatedAtUtc, LastLoginUtc.
- Password policy: min 12 chars, complexity configurable, history of last 5, no reuse of username.
- Brute-force protection: lock account after 5 failures with exponential backoff; every failure audited.
- Auth is verified **in the service** (not in the UI) – the UI never touches the DB directly. Successful login returns a short-lived session token (in-memory, 15 min idle timeout).
- Admin functions: create/disable/delete user, reset password (forces change on next login), change role. Cannot delete/demote the last active Admin.
- **Recovery**: since everything is local, create a one-time **recovery key** at setup (printed/saved by Admin offline) that can reset an Admin password. Document loudly in the UI.
- No password ever logged or stored reversibly.

## 6. Database Schema (SQLCipher)

- `Users` (above)
- `PasswordHistory(UserId, Hash, ChangedAtUtc)`
- `UnblockSessions(Id, UserId, UnblockedAtUtc, ExpiresAtUtc, EndedAtUtc, EndReason[Expired|Manual|Shutdown|Tamper])`
- `AllowedDevices(Id, VidPid, InstanceId, Label, AddedBy)` (phase 2, per-device mode)
- `AuditLog(Id, TimestampUtc, UserId, Action, Details, PrevHash, Hash)` – **hash-chained** so edits/deletions are detectable
- `Settings(Key, Value)` – unblock duration, lockout rules, etc.
- `SchemaVersion` – simple migrations (DbUp or hand-rolled).

Use WAL mode, `PRAGMA foreign_keys=ON`, parameterised queries only (Dapper or EF Core with SQLCipher; recommend **Dapper** for small footprint).

DB location: `%ProgramData%\SAMP\samp.db` with ACL: SYSTEM + Administrators full; Users **no access** (only the service opens it).

## 7. Solution Structure

```
SAMP.sln
├─ src/
│  ├─ SAMP.Core/          # domain models, interfaces (IUsbBlocker, IUserStore, IClock), policy logic
│  ├─ SAMP.Data/          # SQLCipher access, migrations, repositories, key protection (DPAPI)
│  ├─ SAMP.Security/      # Argon2 hashing, password policy, lockout, session tokens
│  ├─ SAMP.Usb/           # RegistryUsbBlocker, PnpUsbBlocker, device enumeration
│  ├─ SAMP.Ipc/           # named-pipe contracts (request/response DTOs), client + server
│  ├─ SAMP.Service/       # Worker Service (UseWindowsService): scheduler, watchdog, IPC server
│  ├─ SAMP.App/           # WPF UI: login, dashboard, users, audit, settings, tray icon
│  └─ SAMP.Installer/     # WiX v4 MSI
└─ tests/
   ├─ SAMP.Core.Tests/
   ├─ SAMP.Data.Tests/
   ├─ SAMP.Security.Tests/
   └─ SAMP.Service.Tests/ # scheduler with fake clock + fake blocker
```

Key abstraction: `IClock` (fake in tests) and `IUsbBlocker` (fake in tests) so the 2-hour logic is fully unit-testable without waiting or touching the registry.

## 8. UI Screens (WPF)

1. **Login** – username/password, lockout messages.
2. **Dashboard** – big status (BLOCKED / UNBLOCKED), countdown to auto-block, Unblock / Block-now buttons (Unblock re-prompts password), connected USB devices list.
3. **Users** (Admin) – list, add, edit, disable, reset password.
4. **Audit log** – filter by user/action/date, integrity-check button (verifies hash chain), export CSV.
5. **Settings** (Admin) – unblock duration, blocking mode, password policy, lockout.
6. **Tray icon** – status colour, quick countdown, notifications. App runs per-user at logon (Run key) and reconnects to the service.

## 9. Security Hardening

- Service ACL: only Administrators may stop/modify it; recovery actions = restart on failure.
- Named pipe ACL: authenticated local users only; every request carries session token; server validates role per command.
- Tamper detection: watchdog restores state, audit entries for registry edits, service stop attempts, clock changes.
- Code-sign binaries and MSI; enable ASLR/DEP; no secrets in logs; zero sensitive buffers where practical.
- Known limit (document it): a local Windows administrator can always bypass any user-mode control (e.g. stop the service, edit registry). Mitigation = tamper audit + restart-on-failure; true prevention needs GPO/Intune/EDR.

## 10. Phased Roadmap

| Phase | Deliverable | Est. |
|---|---|---|
| 0 – Spike | Prove USB block/unblock method on Win10/11; SQLCipher + DPAPI key POC | 2–3 d |
| 1 – Foundation | Solution, Core/Data/Security libs, schema + migrations, user store, hashing, unit tests | 1 wk |
| 2 – Service | Worker service, IPC, UsbBlocker, 2-hour scheduler/watchdog/reconcile, audit chain | 1–1.5 wk |
| 3 – UI | Login, dashboard + countdown, user mgmt, audit, tray | 1–1.5 wk |
| 4 – Hardening | Lockout, tamper detection, ACLs, recovery key, failure/fault-injection tests | 1 wk |
| 5 – Packaging | WiX MSI, code signing, install/uninstall tests, admin guide | 3–4 d |
| 6 – Optional | Per-device allow-list, MTP/phone blocking, auto-lock on idle | later |

## 11. Test Plan

- **Unit**: scheduler with fake clock (expires at exactly 120 min, re-arm after restart, sleep/resume, clock rolled back); password hashing/policy; lockout; last-admin protection; audit chain verification.
- **Integration** (Windows VM): block/unblock with a real USB stick; service killed mid-session → restarts and still blocks on time; reboot during unblock window; user logoff; DB file copied elsewhere cannot be opened without key; wrong DPAPI context fails closed.
- **Security**: attempt DB open with hex editor/`sqlite3` (must fail); pipe calls without token; privilege escalation attempts from Operator role.
- **Manual acceptance**: install on clean Win10 and Win11, standard-user and admin logons.

## 12. Risks & Open Questions

1. Registry-only blocking may not affect already-attached devices or require a re-plug → covered by active enumeration/eject.
2. Windows Update/Defender or AV may flag registry changes → code signing, document exclusions.
3. DPAPI machine-scope means any admin on the machine can derive the key → acceptable for the threat model; optional upgrade: TPM-sealed key.
4. Lost Admin password with no recovery key = unrecoverable by design (data wipe + reinstall).
5. **Questions for you:** (a) Block only USB storage, or also phones (MTP) / all USB? (b) Single shared PC or multiple Windows users? (c) Is 2h fixed, or Admin-configurable? (d) Is a local Windows admin considered trusted? (e) Need per-device allow-list in v1?

## 13. Addendum (rev 2): Mandatory Login/Logout, Tamper-Proof Device Logs, Password-Protected Uninstall

### 13.1 Mandatory login / logout for the entire app

- **Nothing in the UI is reachable before login.** `App.OnStartup` shows only the Login window; the main shell is created only after the service returns a valid session token. No cached/auto-login, no "remember me".
- **Logout**: explicit Logout button + tray menu item; clears the token in the UI, **revokes it in the service** (server-side session table), closes all windows except Login.
- **Automatic logout**: 15 min idle timeout (configurable), Windows session lock / logoff / fast-user-switch (`SystemEvents.SessionSwitch`), and service-side token expiry. A closed or crashed UI leaves its session to expire server-side.
- **Tray behaviour**: when logged out the tray shows only "Login" and "Exit" and read-only status; no countdown details, no unblock.
- Every IPC command except `Login` and `GetPublicStatus` is rejected without a valid token (enforced in the service, not the UI).
- Login, failed login, logout, timeout and lock-triggered logout are all written to the audit log.
- The auto-block timer is independent of login state: logging out or closing the app does **not** cancel or extend the 2h timer.

### 13.2 Device-connection logging service (tamper-proof, local)

New project `SAMP.Monitor` (a second Windows Service, also LocalSystem, mutually supervised with `SAMP.Service`; each restarts the other if stopped and logs the event).

**What it collects** (all USB/PnP devices, not only storage):
- Arrival and removal events via `RegisterDeviceNotification` / WMI `Win32_DeviceChangeEvent`, backed by the `Microsoft-Windows-Kernel-PnP` and `DriverFrameworks-UserMode` event logs (catches events that occurred while the service was down, by replaying them on startup).
- Fields: timestamp UTC, event (connected/removed/blocked/allowed), VID/PID, device class, friendly name, serial number, instance ID, drive letter, interactive Windows user + SAMP user logged in at the time, current block state, and whether it occurred inside an unblock session.
- Also records service lifecycle events: start, stop, crash recovery, clock changes, registry/policy drift.

**Storage**
- **One log file per day**: `%ProgramData%\SAMP\logs\devicelog-YYYYMMDD.db` (UTC date; rolls over at 00:00 UTC, and the service creates the next file on first event). Each is a SQLCipher DB (AES-256) with its own key derived from a DPAPI-sealed master log key (HKDF with the date), separate from the user DB key. Append-only table; DB triggers raise on UPDATE/DELETE.
- **Not readable by other apps**: (1) content is encrypted, so even a copied or opened file is unreadable without the key; (2) folder/file ACL is SYSTEM only (Administrators and Users have no access, inheritance removed); (3) the service holds the current file open with an exclusive share mode (`FileShare.None`), so other processes cannot open it; (4) the only way to read logs is the service's IPC API, which requires an Admin session token (see 13.2 UI).
- The first record of each day links to the last hash of the previous day, so the chain is continuous across files.

**Tamper-evidence**
1. **Hash chain**: each row stores `Seq`, `PrevHash`, `Hash = HMAC-SHA256(key, Seq|Timestamp|Payload|PrevHash)`. Key is DPAPI-sealed (optionally TPM-sealed) and never leaves the service.
2. **Gap detection**: contiguous `Seq`, plus a heartbeat row every minute; missing heartbeats or a sequence jump are flagged as "logging gap" on verification.
3. **External anchors**: every N records and at least hourly, the latest chain head hash is written to (a) the Windows Event Log (custom `SAMP` log) and (b) a second file in a different protected location. Truncating or rolling back the DB then no longer matches the anchors.
4. **Verify** command (Admin UI, "Verify log integrity"): re-walks the chain, compares anchors, reports first broken record. A broken chain raises a persistent red banner and an Event Log alert.
5. Tamper actions on the log (stop service, replace DB file, ACL change) are themselves logged to the Windows Event Log, which the local user cannot silently edit as a standard user.
6. **Retention: 30 days.** A daily job in the service deletes whole daily files older than 30 days (never individual rows). Before deleting, it writes a signed "pruned file X, final hash H" record into the current chain and the Event Log, so legitimate pruning is distinguishable from tampering (a missing file without a prune record is flagged). Files are removed only after they have been successfully copied to the external location, if one is configured.
7. **External log location (configurable)**: Admin sets a local folder, removable/secondary drive, or UNC share in Settings. When a daily file is closed (and the chain head hourly), the service copies the encrypted file plus its anchor to that location (write-once naming, temp file then atomic rename). The copy stays encrypted and chained, so it is verifiable and unreadable without the key. Copy failures, unreachable path, or a changed path are logged and shown as a warning; local logging is never blocked by an unreachable destination (retry queue). Only Admins can change the path, and the change is audited.
8. Export: signed CSV/JSON of a chosen date range (Admin only; includes chain head + HMAC so it can be verified).

**UI**: "Device Log" screen visible **only to Admin role** (menu item is not rendered for Operators/Viewers; the service also rejects log-read, verify, export and external-path commands for any non-Admin token). Filter by date/device/user, integrity status badge. Operators cannot see any logs, including their own.

### 13.3 Uninstall protection with a password

- A single, dedicated **Uninstall Password** is **mandatory at first-run setup** (setup cannot finish without it; separate from login passwords). It is stored as an Argon2id hash in the user DB and verifiable only by the service.
- **Admin-only management**: only Admin-role users can see the "Uninstall protection" settings page and **change** the uninstall password (requires current uninstall password or a fresh Admin re-login, plus the same password policy; change is audited and written to the device log). Operators/Viewers never see or can call these commands; the service enforces the role.
- **MSI enforcement (WiX v4)**:
  - Custom action in `InstallExecuteSequence`, condition `REMOVED="ALL" AND NOT UPGRADINGPRODUCTCODE`, runs *before* `RemoveExistingProducts`/file removal. It reads `UNINSTALL_PASSWORD` (from a password dialog in the UI sequence, or from the command line for silent installs), asks the service to verify it, and returns failure to **abort the uninstall** if wrong. Because it is in the execute sequence it also applies to `msiexec /x … /qn`, not only Add/Remove Programs.
  - 3 failed attempts → 15 min lockout; every attempt audited and written to the tamper log.
  - Upgrades/repairs are unaffected (separate condition) but still require the Admin role.
- **Hardening around the MSI**:
  - Install dir ACL: Users/Administrators read+execute only; only SYSTEM / TrustedInstaller-like service account can modify. Service config (stop/delete) denied to Administrators via service security descriptor except via the verified path.
  - Service recovery: restart on failure; `SAMP.Monitor` re-creates/starts `SAMP.Service` if it is stopped or deleted (and vice-versa).
  - Optional: an integrity checker that, on tamper (files missing, service removed), logs it and keeps the USB policy in the **blocked** state (USBSTOR=4 persists even if the app is deleted, which fails closed).
- **Known limit (documented in the admin guide)**: a local Windows administrator who is prepared to boot to safe mode, take ownership of files, or edit the registry/services offline can still remove the software; no purely user-mode design prevents that. The password stops normal and scripted uninstalls, and tampering is logged and anchored. For stronger guarantees pair with GPO/AppLocker/Intune, BitLocker + BIOS password, or an EDR tamper-protection feature.
- Forgotten uninstall password: recoverable only with the offline recovery key created at setup.

### 13.4 Updated solution layout and roadmap changes

```
src/
  SAMP.Monitor/        # NEW: device-connection logging service
  SAMP.Logging/        # NEW: hash-chained/HMAC append-only log, anchors, verifier
  SAMP.Installer/      # + password dialog, uninstall-guard custom action (C# CA via WiX)
tests/
  SAMP.Logging.Tests/  # chain verification, tamper (edit/delete/truncate/reorder) detection
```

| Phase | Added work |
|---|---|
| 1 | Session table + token revoke/timeout in `SAMP.Security`; uninstall-password storage |
| 2 | `SAMP.Monitor` service, `SAMP.Logging` library, mutual-supervision watchdog |
| 3 | Login-gated shell, logout/idle/session-lock handling, Device Log screen, integrity badge |
| 4 | Tamper tests: edit/delete rows, swap DB file, stop/delete services, clock rollback; anchors check |
| 5 | MSI uninstall guard (`/x`, `/qn`, ARP, scripted) tests; ACLs; signed export |

New acceptance tests: (1) app cannot show any data before login; (2) logout and lock revoke access immediately; (3) editing any row in `devicelog.db` makes Verify fail and points to the record; (4) deleting the DB or services is detected, logged and USB stays blocked; (5) `msiexec /x /qn` without the correct password fails with the product intact.

### 13.5 Decisions (confirmed by owner)
1. **Logs are visible to Admin role only** in the app; log files are encrypted, ACL-locked to SYSTEM and exclusively opened by the service, so no other app can read them.
2. **Retention 30 days, one log file per day.**
3. **External log location is configurable** (Admin-only setting; folder/drive/UNC).
4. **One uninstall password**, set at application setup, changeable by Admin role users only.

Further decisions: block **mass storage only** (keyboards, mice and other HID are never touched), with rules configurable by class, vendor, product and serial (13.6); the auto-block duration is **Admin-configurable** (13.7).

Remaining defaults (not yet answered): multiple Windows users supported; local Windows admins not fully trusted (tamper logged).

### 13.6 Configurable block rules (class / vendor / product / serial)

**Scope**: only USB mass storage is managed. The built-in default rule is "USB mass storage class" (interface class 0x08, hardware/compatible ID `USB\Class_08`, service `USBSTOR`, plus UASP). HID and other classes are never matched unless an Admin explicitly adds a rule for them.

**Rule model** (`BlockRules` table, Admin-managed, audited):

| Field | Meaning |
|---|---|
| Id, Name, Enabled | |
| Action | `Block` or `Allow` (Allow = permanent exception, e.g. company-issued drive) |
| MatchType | `DeviceClass` (class GUID or USB class code), `VendorId`, `VendorId+ProductId`, `Serial` (VID+PID+serial = instance ID) |
| Value | e.g. `08` / `{4d36e967-e325-11ce-bfc1-08002be10318}`, `0951`, `0951:1666`, `0951:1666:001CC0EC34...` |
| Scope | `Always` or `OnlyWhenLocked` (rule applies only when the global state is Blocked) |
| CreatedBy, CreatedAtUtc, Note | |

**Evaluation order** (most specific wins): Serial > VID+PID > VID > Class; at equal specificity `Block` beats `Allow`. Default when nothing matches: mass storage is governed by the global state (Blocked / Unblocked-for-2h); everything else is untouched.

**How the rules are enforced** (in `SAMP.Usb`, behind `IUsbBlocker`; a `RuleCompiler` turns rules into OS state):
1. **Windows Device Installation Restrictions** (`HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`): `DenyDeviceClasses`, `DenyDeviceIDs` (hardware/compatible IDs such as `USB\VID_0951&PID_1666`), `AllowInstanceIDs` (serial-specific allow), with `DenyDeviceIDsRetroactive` so devices already installed are also disabled. This is the primary mechanism and supports class, vendor, product and serial.
2. **Global state fallback**: `USBSTOR\Start` and the Removable Storage policy (section 3) for the all-mass-storage block/unblock.
3. **Immediate effect on connected devices**: on any change, the service enumerates currently attached USB storage devices (WMI/SetupAPI), re-evaluates the rules and disables/ejects (`pnputil /disable-device`) or re-enables each as needed.
4. **Hot-plug**: the Monitor service's device-arrival event triggers a rule check on every new device, so a newly plugged device is evaluated even if policy refresh lags; each decision (matched rule id, action) goes into the tamper-proof device log.

**Unblock session interaction**: unblocking for N minutes lifts the *global* mass-storage block only. Explicit `Block` rules (e.g. a banned vendor) stay in force during the session unless the rule's Scope is `OnlyWhenLocked`. `Allow` rules stay allowed after the session ends. At expiry the compiler re-applies all rules, which restores the full block.

**UI (Admin only)**: "Device Rules" screen: add rule from a **currently/previously connected device** (picks VID/PID/serial automatically from the device log) or by typing values, enable/disable, order preview showing "what would happen to device X" (dry-run), import/export rules (signed JSON). Operators can see the current effective state only.

**Validation**: VID/PID 4 hex digits, serial non-empty, class GUID well-formed; reject a rule that would be a no-op duplicate; confirmation prompt for rules that match everything.

**Phase 0 spike additions**: verify on Win10 22H2 and Win11 that (a) `DenyDeviceIDs` with `USB\Class_08` blocks storage while sparing HID, (b) `AllowInstanceIDs` precedence over a class deny works as designed (policy "apply layered order of evaluation" setting), (c) already-attached devices are disabled without reboot, (d) devices without a serial number (some cheap sticks) are handled: serial rules can't match them, so VID/PID rules are suggested instead.

### 13.7 Admin-configurable auto-block duration

- Setting `UnblockDurationMinutes`, default **120**, allowed range **5 to 1440** (min 5 and max 24 h; the maximum itself is a setting the Admin can lower).
- **Only Admin role** can change it (service-enforced); change is audited and written to the device log with old and new values.
- Applies to **new** unblock sessions. An already-running session keeps its original `ExpiresAtUtc` (stored per session in `UnblockSessions`), so changing the setting can never silently extend an active window. Shortening it can optionally also cap the active session (checkbox "apply to current session", default off).
- Optional per-role cap: Operators pick a duration **up to** the Admin-set maximum at unblock time (default: the configured value, Operators cannot exceed it).
- The dashboard countdown and the 10-min/1-min warnings are computed from the stored expiry, not hard-coded, so they work for any duration (warning times are scaled down for very short durations).
- Tests: change duration mid-session; boundary values (5, 1440, out of range rejected); restart after changing duration; Operator cannot change it.

## 14. Next Step

Approve the plan (and answer the open questions in §12), then start Phase 0/1: scaffold the solution with `dotnet new` on a Windows machine (WPF and the service target `net8.0-windows`, so they can't be built or run from this Linux environment; `SAMP.Core`/`Security`/`Data` can be built and unit-tested here on `net8.0`).

## 15. Status

**Phase 1 (done, tested on Linux):** Core, Security, Data (SQLCipher, users, sessions, uninstall password, hash-chained audit).

**Phase 2 (code complete; 110 unit tests pass on Linux; Windows-only parts unverified):**
- `SAMP.Usb`: rule evaluator/validator, device-install-policy compiler, `RegistryUsbBlocker`, `UnblockManager` (configurable window, watchdog tick, reconcile, clock-rollback and drift detection), `BlockRuleService`.
- `SAMP.Logging`: per-day encrypted device log, HMAC chain across days, external anchors, 30-day pruning, external replication.
- `SAMP.Ipc`: named-pipe JSON transport, ACLs, partner-service supervisor.
- `SAMP.Service`: command API with session/role enforcement, monitor API, watchdog and pipe workers, DPAPI key setup.
- `SAMP.Monitor`: WMI device sensor that reports to the service.

**Not verified (needs Windows, Phase 0 spike):** registry/device-install policy behaviour, `WindowsDeviceController` (WMI + `pnputil`), WMI event source, DPAPI key store, pipe ACLs, service install/recovery settings, Windows Event Log anchor sink and replay of missed PnP events (not implemented yet).

**Phase 3 (code complete; compiles incl. XAML; view-models and client contract tested on Linux; UI never run):**
- `SAMP.Client`: typed `ISampService` over the named pipe (session token held inside; raises `SessionExpired`).
- `SAMP.App.Core`: MVVM view-models. `ShellViewModel` enforces Setup -> Login -> (forced password change) -> Main; sign-out on logout, 15 min idle, Windows lock/logoff, or service-side session end. Admin-only pages are not even created for Operators/Viewers.
- `SAMP.App` (WPF, net8.0-windows): views, tray icon (signed-out tray shows only Open/Exit), idle and session-lock hooks, closing the window signs out and hides to tray, unblock re-prompts for the password.
- Service additions: `auth.verify` command and `me` allowed during forced password change.

**Phase 4 (code complete; 158 tests pass on Linux; Windows-only parts unverified):**
- Offline **recovery key** created at setup (shown once, only its Argon2id hash stored). Resets a lost Admin password, unlocks the account, revokes its sessions, rotates the key; 5 wrong attempts lock recovery for 15 min. UI: key screen at setup (must confirm), "Forgot password?" flow.
- **Login throttle** across all accounts and unknown names (10 failures/min -> 30 s cooldown); pipe connections that go silent are dropped after 30 s.
- **Integrity monitor**: device log and audit log are verified at start and hourly; a failure raises a persistent alert (login screen API, dashboard banner, Audit page) that only an Admin can acknowledge; unchanged damage does not re-alert.
- **Unclean shutdown detection** (`service.unclean_shutdown`) at the next start.
- **Fail-secure fixes**: unreadable OS policy state is treated as "not blocked" and re-applied; a failed registry write at expiry still ends the window and is retried next tick.
- Fault-injection tests: registry failures at expiry/reconcile, device controller failure, unreadable policy, corrupt/truncated database, failing device log during audit mirroring.
- Windows-only, unverified: `ServiceSecurity` SDDL (admins read-only, SYSTEM full; applied by the installer), `EventLogAnchorSink` (Application log, source "SAMP"), pipe ACLs.

**Phase 5 (written; Inno Setup installer never compiled or run; guard, service side and script consistency tested on Linux):**
- **Inno Setup** (`installer/SAMP.iss`, `installer/build.ps1`) replaces the earlier WiX/MSI approach, which was removed: one `SAMP-Setup-<version>.exe` wizard, self-contained .NET 8 files, two LocalSystem auto-start services created with `sc.exe` (restart on failure), autostart + Start-menu entry.
- **Protected upgrade/uninstall:** because Setup does not run as SYSTEM, the services restrict themselves (SYSTEM full, Administrators read-only) and open a 15-minute **maintenance window** only after the service verifies the uninstall password (`maintenance.begin`, Argon2id + lockout). The password reaches `SAMP.UninstallGuard.exe --begin-maintenance --password-file` through a temp file that is wiped, never a command line. Wrong/locked/unreachable aborts before anything is touched; silent runs use `/UNINSTPASSWORDFILE=`.
- Uninstall: password dialog (masked), services disabled -> stopped -> deleted, then `--restore-policy` returns USB storage to normal. Upgrades over an existing install need the password too.
- Docs: `installer/README.md` (incl. Windows first-install checklist), `docs/ADMIN_GUIDE.md`.

**Next:** a Windows verification pass: Phase 0 spike items, the installer checklist, then fixes found there.

