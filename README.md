# PCIntegrityRepair (2026-09-17 build)

Windows system-integrity audit and repair suite: catalog evidence, servicing
ownership, volume headers and firewall driver verification.

## Tools

- `Invoke-PCIntegrityAudit.ps1` - run the full integrity audit
- `Build-RepairPackage.ps1` - package the repair kit
- `Find-FirewallDriverCatalog.ps1` / `Invoke-FirewallFileVerification.ps1` - firewall driver catalog evidence
- `Find-PnpCatalogEvidence.ps1` / `Find-ServiceCatalog.ps1` - driver/service catalog inspection
- `Inspect-RebootEvidence.ps1` / `Inspect-ServicingOwners.ps1` / `Inspect-VolumeHeaders.ps1` - reboot, servicing and volume evidence
- `Cancel-TxrCleanupQueue.ps1` - cancel TXR cleanup queue
- `CatalogEvidence.cs` - native catalog evidence helper

`LOGIN-RECOVERY.txt` - read before rebooting after any repair run.
