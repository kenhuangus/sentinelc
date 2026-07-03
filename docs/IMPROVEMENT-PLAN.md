# SentinelC Improvement Plan

This document is the current state after the July 2026 hardening pass. Older
items that are already implemented have been moved into the completed section so
the remaining plan does not describe stale work.

## Implemented And Verified In Code

- Build hardening flags are enabled in `build.ps1`, `build.sh`, and `Makefile`:
  stack protector, FORTIFY, format-string checks, ASLR, DEP, and high-entropy
  ASLR.
- Response safety is hardened in `respond.c`: expanded critical-process guard,
  fail-closed unresolved PID handling, handle-based process validation, and
  reparse-safe quarantine.
- Signature uncertainty is not treated as clean in security-relevant process and
  service paths. Current rules include `PROC.UNVERIFIED_SIG` and
  `SVC.UNVERIFIED`.
- Fleet Console read APIs require the console token, ingest requires per-host
  tokens, malformed host path decoding returns 400, and upload helpers reject
  non-loopback plaintext HTTP.
- Elevated PowerShell helpers pass arguments through JSON handoff files and use
  system tool paths instead of Windows search order.
- Offline-like hive fallback uses a random, SYSTEM/Admin-only scratch directory
  and launches `powershell.exe`/`reg.exe` by absolute System32 path.
- Targeted file scanning streams full file contents for YARA-lite and string IOC
  checks, with overlap between chunks.
- FIM `--integrity` rehashes file contents by default and no longer trusts
  size+mtime or a large-file sentinel hash. Baselines are authenticated with
  HMAC-SHA256 and a DPAPI-wrapped key.
- Built-in false-positive suppression only auto-suppresses Microsoft-signed
  noisy rules. Explicit `suppress.txt` signer rules remain user policy.
- High-value user-mode coverage is present:
  `PROC.LOLBIN_ARGS`, `PROC.ENCODED_CMD`, `PROC.PPID_SPOOF`,
  `CRED.LSASS_HANDLE`, `CRED.SENSITIVE_FILE`, `MEM.SHELLCODE`,
  `MEM.REFLECTIVE_PE`, `PROC.HOLLOWED`, `EVADE.AMSI_PATCH`,
  `EVADE.ETW_PATCH`, `PERSIST.APPCERT`, `PERSIST.LSA_PROVIDER`,
  `PERSIST.SILENT_EXIT`, `PERSIST.SVC_REGISTRY`, and
  `PERSIST.TASK_COMHANDLER`.
- `heur.c` path classification canonicalizes Windows paths, lowercases them,
  expands short names when possible, and uses segment-boundary checks instead
  of substring classification.
- `scan_persist.c` scheduled-task parsing sanitizes comments/CDATA, understands
  namespaces/attributes, scans each Exec action independently, decodes common
  XML entities, and emits ComHandler actions.

## Remaining Highest-Value Work

1. **Persistent signature cache.**
   The in-process signature cache exists, but cold scans still reverify every
   file. Add `%ProgramData%\SentinelC\sign_cache.tsv` keyed by path, size, and
   mtime.

2. **PE analysis cache.**
   Cache `pe_analyze` by path, size, and mtime and stash `PeInfo` on `ProcRec`
   so process, keylogger, service, file, and correlation paths do not repeat the
   same PE parse work.

3. **Parallel FIM hashing.**
   `scan_integrity.c` correctly streams every tracked file now. Add a producer
   plus worker pool after making `list_add` thread-safe.

4. **Full YARA engine or larger supported subset.**
   The current `yara_lite.c` is useful but not libyara. Decide whether to embed
   libyara or clearly define the supported subset and add tests for it.

5. **Code signing and release hardening.**
   Production distribution needs a signed binary and installer so SmartScreen
   and AV reputation do not dominate first-run trust.

6. **Kernel-driver design remains future work.**
   A signed driver is still the only honest way to get kernel-vantage rootkit
   visibility and blocking. It requires WDK/MSVC, signing, and a different
   release process.

## Performance Notes

- Correctness currently wins over speed for FIM: integrity checks intentionally
  rehash content every run to catch timestomped or metadata-preserving changes.
- Full scans now include memory, credential, and evasion checks. Performance
  work should focus on avoiding repeated PE/signature work rather than weakening
  detection defaults.

## Documentation Rule

When a planned item is implemented, move it into the completed section with the
rule names or files that prove it exists. Do not leave completed work listed as
future roadmap.
