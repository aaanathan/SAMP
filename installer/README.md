# SAMP installer (Inno Setup)

Produces a single setup program, `artifacts\SAMP-Setup-<version>.exe`, with the usual wizard (install, upgrade,
uninstall from Settings > Apps) built with **Inno Setup 6.4+**.

```powershell
.\installer\build.ps1 -Version 1.0.0        # Windows, needs the .NET 8 SDK and Inno Setup 6.4+
```

> **Unverified.** `SAMP.iss` has been checked only by static tests (`tests/SAMP.Installer.Tests`); Inno Setup is
> Windows-only, so the script has never been compiled or run here. Work through the checklist at the end.

## What setup does
| Step | Details |
|---|---|
| Files | Self-contained .NET 8 build (no prerequisites) in `%ProgramFiles%\SAMP` |
| Services | `SAMPService` and `SAMPMonitor`: LocalSystem, automatic start, restart after every failure (5 s), created with `sc.exe` |
| Autostart / shortcut | `HKLM\...\Run\SAMP` starts the UI at every logon; Start-menu shortcut |
| Data | `%ProgramData%\SAMP` is created by the service (SYSTEM-only). Setup and uninstall **do not delete it**. |

## Protection of upgrade and uninstall
The services restrict themselves at every start (SYSTEM full control, Administrators read-only), so even an elevated
`sc stop`/`net stop` is refused. Setup is *not* SYSTEM, so it needs a door that only the uninstall password opens:

1. Setup / uninstall asks for the **uninstall password** (wizard page, or the dialog at uninstall).
2. The password is written to a temporary file (never a command line) and handed to
   `SAMP.UninstallGuard.exe --begin-maintenance --password-file ...`, which wipes and deletes the file.
3. The guard calls the service (`maintenance.begin`). The service checks the Argon2id hash, enforces the lockout
   (3 wrong attempts = 15 min) and, only if correct, relaxes its own service permissions for **15 minutes**.
4. Setup then disables, stops and deletes the services, replaces/removes files, and (uninstall) runs
   `--restore-policy` so USB storage works again.
5. A wrong password, a lockout, or an unreachable service aborts the change before anything is touched
   (fails closed). The window closes by itself, and any service restart re-applies the restriction.

First installs have no password step. **Upgrades and reinstalls over an existing install need the password too.**

### Silent installs / uninstalls
```bat
SAMP-Setup-1.0.0.exe /VERYSILENT /UNINSTPASSWORDFILE=C:\secure\pw.txt
"%ProgramFiles%\SAMP\unins000.exe" /VERYSILENT /UNINSTPASSWORDFILE=C:\secure\pw.txt
```
`/UNINSTPASSWORD=<pw>` also works but is visible in the process list; prefer the file (first line = password).

## Known limits
* A local administrator who boots to safe mode, takes ownership of the service keys/program folder, or deletes files
  offline can still defeat any user-mode protection. The tamper log, anchors and integrity alerts make it visible; for
  stronger guarantees add BitLocker + BIOS password, AppLocker/WDAC or an EDR tamper policy. Sign your releases.
* During the 15-minute maintenance window an administrator can stop the services (that is its purpose).
* If the installation is damaged so the guard or service is gone, the password cannot be verified and setup refuses.
  Delete the old install by hand (administrator), then install fresh; the encrypted data cannot be reused elsewhere.

## First-install checklist (clean Windows 10 and 11 VMs)
1. Run `SAMP-Setup-<v>.exe` as administrator; both services are Running/Automatic. Launch SAMP: first-run setup (Admin, uninstall password, recovery key).
2. Plug in a USB stick: blocked. Unblock from the dashboard: it mounts. Let the window expire (or set 5 minutes): it disconnects and blocks.
3. Elevated `sc stop SAMPService` / Services console: access denied. Kill the process in Task Manager: restarts within about 5 s, `service.unclean_shutdown` is logged.
4. Run setup again (or a newer build): the password page appears; wrong password x3 locks it; correct password upgrades, data and settings survive.
5. Uninstall from Settings > Apps: password dialog; wrong password aborts and leaves everything installed; correct password removes SAMP and USB storage works afterwards.
6. Silent uninstall without a password fails; with `/UNINSTPASSWORDFILE` succeeds.
7. Reboot during an unblock window: the window resumes with the remaining time and ends on schedule.
8. Device Log > Verify integrity passes; a standard user cannot open `%ProgramData%\SAMP`.
