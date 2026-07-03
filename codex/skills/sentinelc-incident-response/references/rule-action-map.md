# SentinelC Rule Action Map

Use this map after parsing SentinelC findings. Always combine the rule with path, signature, hash, parent process, persistence source, and user intent.

## Act First

- `OFFLINE.DEFENDER_EXCLUSION`, `TAMPER.DEFENDER_EXCLUSION`: remove broad or user-writable exclusions unless the user confirms a short-lived testing need. Export the Defender exclusions key before changes.
- `FILE.YARA_MATCH`: hash the full file, inspect the matched offset if available, and quarantine only after preserving a copy. For non-executable files with embedded `MZ`/`PE`, extract and hash the embedded blob.
- `RK.HIDDEN_PROC`, `RK.HIDDEN_FILE`, `RK.SUSPICIOUS_DRIVER`: collect evidence, do not delete kernel components blindly, and verify with offline-like scan or trusted offline tooling.
- `PROC.ENCODED_CMD`: capture full command line and parent. Decode and attribute before killing. Known automation may legitimately use encoded commands.
- `PROC.RWX_MEM`, `MEM.*`, `CORR.IMPLANT`: suspend or isolate only after confirming the process is not known JIT, browser, Electron, security tooling, or developer tooling.

## Investigate Then Disable

- `PERSIST.RUNKEY`, `OFFLINE.RUNKEY`, `OFFLINE.USER_RUNKEY`: disable unwanted startup values. Reinstall or update apps with invalid signatures before deleting app files.
- `PERSIST.TASK`: export task XML first. Disable or delete only unwanted user-writable tasks, suspicious script launchers, or unsigned targets.
- `SVC.UNSIGNED`, `SVC.USERWRITABLE_PATH`, `OFFLINE.BOOT_DRIVER`: export service configuration first. Disable services when path, signature, and vendor context support risk. Do not remove boot drivers without rollback.
- `NET.LISTEN_SUSPICIOUS_PROC`, `NET.BEACON`, `NET.IOC_MATCH`: confirm listener address and expected use. Stop or disable apps that expose local services unexpectedly.
- `KEY.LL_HOOK`, `KEY.RAW_INPUT`, `SPY.MULTI_CAPTURE`: treat as privacy-sensitive. Signed OEM accessibility/audio/pairing utilities may be benign; disable if unwanted.

## Usually Review Noise

- `FILE.PACKED` under signed Windows or driver resource paths: review only unless unsigned, recently dropped, or correlated with persistence.
- `PERSIST.LSA_PROVIDER` signed Microsoft entries: no action unless unsigned or non-Microsoft provider appears.
- `CORR.MULTI_SIGNAL` on validly signed productivity/developer apps: review and suppress only after attribution.
- Store app reparse points with zero-byte launchers: do not hash/delete as normal files; repair/reinstall the package or remove only autostart.

## Reporting Template

For each lead, report:

1. Finding and evidence.
2. Live verification result.
3. Action taken or reason for no action.
4. Evidence location.
5. Verification result after cleanup.
