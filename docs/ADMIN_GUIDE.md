# SAMP – Administrator guide

## Roles
| Role | Can do |
|---|---|
| Admin | Everything: users, device rules, settings (auto-block duration, external log path, uninstall password), device and audit logs |
| Operator | Unblock/block USB storage (re-enters password to unblock, up to the configured duration), change own password |
| Viewer | See status only |

Only Admins can see the device log, audit log, rules and settings; the service enforces this, not just the UI.

## First run
1. Start **SAMP**. Create the administrator account and the **uninstall password** (different from the login password).
2. Write down the **recovery key** shown once. It is the only way to reset a lost Admin password. Store it offline.
3. Sign in. USB storage is blocked until someone unblocks it.

## Everyday use
* **Unblock**: Dashboard, choose minutes (default 120, configurable by Admins), re-enter your password. The countdown
  runs in the service: it blocks again at the end even if the app is closed, you sign out, or the PC restarts.
  Warnings appear at about 10 minutes and 1 minute.
* **Sign-out**: automatic after 15 minutes without input, when Windows is locked, or when you log off. Closing the window also signs out.
* **Rules** (Device Rules): allow or block by class, vendor, vendor+product or serial. Most specific wins; Block beats Allow on a tie.
  The easiest way to add one is Device Log > select an event > *Create rule from selected*.

## Settings
* *Auto-block duration* / *maximum*: 5-1440 minutes; changes apply to new windows (a running one is never extended).
* *External log location*: folder, drive or UNC path. Closed daily log files are copied there (still encrypted). Local logs are kept 30 days; a day is deleted only after its copy exists when a location is set.
* *Uninstall password*: change it with the current password, or with your own login password if forgotten.

## Logs and integrity
* Device events and every audit event go to a per-day encrypted file under `%ProgramData%\SAMP\logs`, chained with HMACs and anchored in a second folder and the Windows Application event log.
* The service verifies both logs at start and hourly. A red banner (dashboard) and an alert (Audit Log page) mean something was altered, deleted or truncated. Investigate first, then **Acknowledge**.
* `service.unclean_shutdown` entries mean the service was killed or the machine lost power.

## Lost passwords
* **Admin login**: *Forgot password?* on the sign-in screen with the recovery key (5 wrong tries = 15 min lock). A new key is issued; store it.
* **Uninstall password**: an Admin changes it in Settings using their own login password.
* **Both lost**: there is no back door by design. Remove the old install by hand as an administrator and install fresh (data is lost).
* **Upgrades**: running a newer setup over an existing install asks for the uninstall password, like uninstalling does.

## Backup
The database and log keys are protected by Windows DPAPI for this machine only, so file copies of `%ProgramData%\SAMP` cannot be opened elsewhere. Use the external log location for off-box copies of the logs.
