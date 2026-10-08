WINDOWS CATALOG CORRUPTION REPAIR

REBOOT READINESS IS NOW CHECKED ON EVERY COMPLETED INTEGRITY RUN.
Exit 0: configured checks passed; not a guarantee or an actual reboot test.
Exit 3: repair/check could not complete. Exit 4: integrity clean but readiness
needs attention. Never interpret exit 4 as permission to reboot safely.
The added checks cover DISM component-store integrity, online system-volume
CHKDSK, boot configuration, boot/system driver file trust, critical process
binary trust, essential services, present-device faults, recent storage/hardware/
crash/service events, pending protected-file operations, Windows RE registration,
crash-dump prerequisites and encrypted-volume recovery requirements.
Unavailable checks and incomplete event history are reported as attention items.
Historical events are retained, not silently erased or declared resolved.
Reports: reboot-readiness.json and reboot-inventory.json inside each run's evidence.
These checks do not emulate the next boot, test all RAM/firmware, prove a backup
restorable, or diagnose crash dumps. No reboot, BCD edit, driver removal, broad
permission reset, event-log clearing, or pending-queue clearing is performed.
Boot/system driver trust is checked before repair as well as after. Missing
registrations may be restored from exact matching, validated Microsoft-signed
component-store or driver-store catalogs. Modern dual-signed drivers additionally
use Windows Driver multiple-signature verification with a required Microsoft root.
Vendor-only Authenticode success is not accepted as a substitute for driver trust.
If registration returns access denied, at most two additional attempts are made,
each after a servicing-idle check and catalog-hash revalidation. No permission
changes or process termination are used. Concurrent copies of this script are
blocked by a named mutex; unrelated Windows servicing is observed separately.
The readiness code is embedded in the delivered PS1; no companion script needed.
In repair mode, if both automatic paging and explicit pagefile configuration are
absent, the script restores system-managed paging (authorized by the owner).
The previous setting is saved in paging-before.json; the verified setting in
paging-after.json. This may require reboot to activate. CheckOnly makes no such
change. A configured pagefile is never presented as an already active pagefile.

Extract the entire ZIP into a writable folder. Right-click Run-Repair.cmd and
choose Run as administrator. Keep the console open. No automatic reboot occurs.
To test without repair: Run-Repair.cmd -CheckOnly

The script addresses the confirmed missing Microsoft catalog registration and
SbatLevel.cat corruption pattern. It does not promise to fix all possible faults.
It verifies the full protected-file set before/after repairs and returns success
only for an explicit clean SFC result. English SFC conclusions are recognized;
unrecognized output fails closed. Genuine servicing reboot markers are honored.

Progress: native stdout/stderr stream live, including carriage-return percentage
updates. One in-place status panel refreshes every five seconds, without repeated
scrollback lines. Preflight identifies the processes blocking our scan, shows new
activity from the actual CBS.log (with its source timestamp), and reports CBS log
age, sampled CPU-time changes, quiet interval, and time until timeout. A CBS record
is the latest observed activity, not a claim about the exact instruction Windows
is executing. Only process/activity changes are printed as new lines.
File hashing and catalog indexing show item counts.
No invented overall percentage is displayed. Some individual OS/API calls may
block: no software can guarantee Windows will never hang.

Default native observation timeout: 1800 seconds per command. Override with
-NativeTimeoutSeconds 3600 if needed. A timeout is NOT completion or cancellation:
the independent worker keeps draining/logging the running native command, saves
its final receipt, and is not killed. The controller stops with a failure status
and prints the worker PID and evidence files. Do not blindly launch another run.
The worker and its command specification are generated inside evidence/ so the
repair PS1 has no companion-script dependency. Do not delete active evidence.

The packaged Repair-WindowsCatalogCorruption.ps1 embeds the verified Microsoft
SignTool executable and its SHA256. It recreates the executable in its evidence
directory and checks the hash and Microsoft signature before using it. The PS1
can be copied alone; no installed SDK or companion Tools folder is needed.
The extra Tools/signtool.exe is retained for package verification, not required at
runtime. Windows supplies SFC, PowerShell 5.1, WinTrust and matching component-store
catalogs. Missing or damaged Windows foundations cannot be synthesized safely:
the script stops instead of inventing trusted data or bypassing trust checks.
No Windows catalogs or personal logs are bundled. No signing-policy bypass or
protected-file copying is used.

Logs/receipts are written under evidence/ beside the script. Native logs are
saved continuously; result.json records the overall outcome and pending queue.
The pending operation queue is observed only, never cleared by this script.

Tests included: Test-StandaloneCatalogRepair.ps1 (reference membership test is
specific to the original driver version); Test-LiveCatalogProgress.ps1 (harmless
synthetic streaming and timeout checks). No test intentionally corrupts Windows.
