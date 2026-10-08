WINDOWS CATALOG CORRUPTION REPAIR

Extract the entire ZIP into a writable folder. Right-click Run-Repair.cmd and
choose Run as administrator. Keep the console open. No automatic reboot occurs.
To test without repair: Run-Repair.cmd -CheckOnly

The script addresses the confirmed missing Microsoft catalog registration and
SbatLevel.cat corruption pattern. It does not promise to fix all possible faults.
It verifies the full protected-file set before/after repairs and returns success
only for an explicit clean SFC result. English SFC conclusions are recognized;
unrecognized output fails closed. Genuine servicing reboot markers are honored.

Progress: native stdout/stderr stream live, including carriage-return percentage
updates. A heartbeat appears every five seconds during native execution and
servicing settle waits. File hashing and catalog indexing show item counts.
No invented overall percentage is displayed. Some individual OS/API calls may
block: no software can guarantee Windows will never hang.

Default native observation timeout: 1800 seconds per command. Override with
-NativeTimeoutSeconds 3600 if needed. A timeout is NOT completion or cancellation:
the independent worker keeps draining/logging the running native command, saves
its final receipt, and is not killed. The controller stops with a failure status
and prints the worker PID and evidence files. Do not blindly launch another run.
The worker and its command specification are generated inside evidence/ so the
repair PS1 has no companion-script dependency. Do not delete active evidence.

Tools/signtool.exe is copied from the existing Microsoft Windows SDK on this PC
for this local-use package. Windows supplies SFC, PowerShell 5.1, WinTrust and the
component-store catalogs. No Windows catalogs or personal logs are bundled.
If Tools/signtool.exe is absent, the script checks the original installed SDK path.
Keep the package intact. No signing-policy bypass or protected-file copying is used.

Logs/receipts are written under evidence/ beside the script. Native logs are
saved continuously; result.json records the overall outcome and pending queue.
The pending operation queue is observed only, never cleared by this script.

Tests included: Test-StandaloneCatalogRepair.ps1 (reference membership test is
specific to the original driver version); Test-LiveCatalogProgress.ps1 (harmless
synthetic streaming and timeout checks). No test intentionally corrupts Windows.
