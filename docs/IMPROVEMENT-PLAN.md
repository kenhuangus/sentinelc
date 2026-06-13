# SentinelC Improvement Plan

Synthesis of three parallel audits (code security, detection coverage, scan
performance), turned into a phased, prioritized implementation plan. Each item
lists the source finding, the files it touches, effort (S/M/L), and expected
impact. Phases are ordered so safety-critical fixes land first, then cheap
high-value detections, then the performance work that makes the heavier
detections affordable, then the larger engineering.

## Headline findings

- **Security:** the core parsers are sound (the prior 11-bug pass holds), but the
  one destructive path, quarantine in `respond.c`, is TOCTOU- and
  junction-abusable, and several consumers treat "could not verify signature" as
  "safe." Build is missing cheap exploit-mitigation flags (ASLR/DEP are already
  on by default under MinGW; stack canaries and FORTIFY are not).
- **Coverage:** strong on persistence and host triage, but two structural holes:
  zero credential-access detection (it caught the infostealer's persistence and
  C2, not the theft), and no LOLBin command-line inspection (signed-binary proxy
  execution walks past every rule). Every IAT-based heuristic is defeated by
  packing.
- **Performance:** `pe_analyze` runs ~10x redundantly (762 calls for 71 unique
  images) and is the biggest cost; `--integrity` re-hashes everything every run;
  the signature cache does not persist across runs. Full scan is ~63 s warm,
  and most of it is avoidable.

## Phase 1 — Safety and correctness hardening (do first)

1. **Handle-based, reparse-safe quarantine.** (security H1/H2/L4, `respond.c`)
   Open the target with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`,
   reject reparse points and directories, and perform both the move and the
   deny-all ACL by **handle**, not by path string. Pre-create
   `%ProgramData%\SentinelC\quarantine` once with an Admins/SYSTEM-only DACL and
   verify it is not a junction. Drop `MOVEFILE_REPLACE_EXISTING`; fail closed if
   the destination exists. Effort M. Impact: closes the only privilege-relevant
   bug, a local-attacker file-redirect/ACL-redirect primitive.
2. **Stop treating `SIGN_UNKNOWN` as clean.** (security H4, `scan_process.c`,
   `scan_persist.c`, driver inventory) In security-relevant locations (system
   dirs, autostart, drivers), route un-verifiable signatures to
   "suspicious-pending" with a "signature could not be verified" note, rather
   than letting them fall through as benign. Effort S. Impact: removes a silent
   false-negative class.
3. **Harden the never-kill guard.** (security M1/M2, `respond.c`) Expand the
   critical-name list (add MemCompression, Registry, fontdrvhost, dwm, and a
   System32-MS-signed catch-all); fail **closed** when a PID cannot be resolved
   (protected processes currently slip through); resolve and act on a **single
   validated handle** so the PID cannot be recycled across the confirmation
   prompt. Effort M. Impact: prevents killing the wrong/critical process.
4. **Add build-hardening flags.** (security M7, `Makefile`, `build.sh`,
   `build.ps1`) Add `-fstack-protector-strong -D_FORTIFY_SOURCE=2
   -Wformat -Wformat-security -fno-strict-aliasing`, keep explicit
   `-Wl,--dynamicbase,--nxcompat,--high-entropy-va`. Document an MSVC release
   path with `/guard:cf /CETCOMPAT /Qspectre /sdl` for Control Flow Guard, which
   MinGW cannot emit. Verified to compile clean. Effort S. Impact: real
   exploit-mitigation on the many fixed stack buffers fed attacker data.
5. **Canonicalize paths before classification.** (security M4, coverage evasion,
   `heur.c`) Replace substring `path_classify` / `name_is_masquerade` matching
   with `GetFullPathNameW` + `GetLongPathNameW` + segment-boundary prefix checks.
   Effort M. Impact: foundational. The current substring match is an evasion
   primitive that neuters every `path_is_user_writable`-gated rule; this fix
   strengthens process, persistence, and driver detection at once.

## Phase 2 — High-value coverage quick wins (small effort, big gains)

6. **LOLBin command-line inspection.** (coverage #1, T1218, `scan_process.c`)
   The single biggest evasion blind spot: signed `rundll32`/`regsvr32`/`mshta`/
   `msiexec`/`installutil`/`msbuild` pass every current rule. The cmdline is
   already collected; inspect it for a LOLBin host plus a suspicious module arg
   (URL, AppData/Temp path, `scrobj.dll`, `javascript:`, comma-entrypoint into a
   writable DLL). New rule `PROC.LOLBIN_ARGS`, SEV_HIGH. Effort S.
7. **Live encoded-PowerShell detection + decode.** (coverage #2, T1059.001,
   `scan_process.c`) The `-enc`/`FromBase64`/`IEX`/`DownloadString` logic already
   exists but only inside scheduled-task XML. Port it to live process cmdlines
   and base64-decode the `-enc` blob (UTF-16LE) to re-scan for IOCs. New rule
   `PROC.ENCODED_CMD`. Effort S.
8. **Accessibility IFEO + SilentProcessExit.** (coverage #3, security-adjacent,
   T1546.008, `scan_persist.c`) Force SEV_CRIT when an IFEO Debugger targets
   sethc/utilman/osk/magnify/narrator/displayswitch, and also read
   `SilentProcessExit\<img>\MonitorProcess`. New rule
   `PERSIST.IFEO_ACCESSIBILITY`. Effort S, near-zero false positives.
9. **AppCertDLLs + LSA providers.** (coverage #4, T1546.009/T1547.005,
   `scan_persist.c`) Clone the existing AppInit scanner for
   `Session Manager\AppCertDlls` and the LSA `Security/Authentication/Notification
   Packages`. Rules `PERSIST.APPCERT`, `PERSIST.LSA_PROVIDER`. Effort S.
10. **Robust scheduled-task XML parsing.** (security M3, coverage, `scan_persist.c`)
    The current `strstr("<Command>")` parser is spoofable with XML comments,
    CDATA, attributes, and namespaces (a parser-differential vs. Task Scheduler).
    Strip comments/CDATA first, or switch to the MSXML reader (COM is already
    initialized in this module). Also inspect triggers and the `ComHandler`
    action. Effort M.

## Phase 3 — Performance (make the heavier scans affordable)

11. **Cache `pe_analyze` by path+mtime; stash `PeInfo` on `ProcRec`.**
    (performance #1, `pe.c`, `scan_process.c`, `scan_keylog.c`, `sentinelc.h`)
    Compute once in `scan_process`, store on the `ProcRec`, and have
    `scan_keylog` reuse it. Eliminates the 762→71 redundancy. Effort M. Impact:
    **cuts full scan ~30-40 s (about 50-60%)**, the single biggest win, and makes
    the Phase 2 cmdline rules effectively free.
12. **Section-only entropy in `pe_analyze`.** (performance #2, `pe.c`, `heur.c`)
    Stop hashing entropy over the whole file just for the packer heuristic;
    per-section entropy is already computed and enough. Effort S. Multiplies #11.
13. **`--integrity`: skip re-hash on size+mtime match.** (performance #3,
    `scan_integrity.c`) Look up the prior baseline entry; if size and mtime are
    unchanged, copy its hash instead of re-reading the file. Effort M. Impact:
    turns the ~10-minute check into seconds when little changed. Tradeoff: misses
    a content edit that preserves size and mtime (timestomp). Keep `--baseline`
    a full hash and add a `--integrity-rehash` flag for paranoid runs; document
    it. Pairs with coverage #10 (timestamp-anomaly flag) to cover the tradeoff.
14. **Persist the signature cache across runs.** (performance #4, `sign.c`)
    Write `%ProgramData%\SentinelC\sign_cache.tsv` (path + mtime + size ->
    verdict + signer) on exit, validate on load. Effort M. Impact: removes ~71
    catalog verifications and their full-file hashes from every cold run.
15. **Fix `enum_proc_modules` O(n^2) dedup.** (performance #8, `scan_keylog.c`)
    Cache module path strings in an array and dedup against the cache instead of
    re-calling `GetModuleFileNameExA` per pair. Effort S. Pure waste removal.

## Phase 4 — Credential-access coverage (the missing threat class)

16. **LSASS handle / credential-dump detection.** (coverage #6, T1003.001,
    new `scan_creds.c`) Walk `NtQuerySystemInformation(SystemHandleInformation)`
    (the ntdll plumbing already exists) for non-MS / user-writable processes
    holding `PROCESS_VM_READ` handles to lsass. New rule `CRED.LSASS_HANDLE`,
    SEV_CRIT. Effort M.
17. **Sensitive-file / hive / browser-credential access.** (coverage #7,
    T1003.002/T1555.003, `scan_creds.c`) Extend the handle walk to flag suspect
    processes with open handles to SAM/SECURITY hives, browser `Login Data`,
    `key4.db`, cookie stores. New rule `CRED.SENSITIVE_FILE`. Effort M. Impact:
    directly detects the infostealer **theft** behavior this tool only half-caught.
18. **Services created directly in registry.** (coverage #8, T1543.003,
    `scan_persist.c`) Walk the Services hive and cross-check against the SCM
    view; inspect FailureCommand recovery actions. Rule `PERSIST.SVC_REGISTRY`.
    Effort M.
19. **Parent-PID spoof detection.** (coverage #9, T1134.004, `scan_process.c`)
    Compare child vs. claimed-parent `CreateTime` (already in the struct, just
    unread); a child older than its parent indicates a forged PPID. Rule
    `PROC.PPID_SPOOF`. Effort M.

## Phase 5 — Larger engineering (roadmap)

20. **Parallelize the FIM hasher and the `scan_process` prologue.**
    (performance #5/#6) A producer enumerates, N worker threads hash; fan the
    per-process fill across the existing pool instead of running 381 processes
    serially before any other scanner starts. Effort L. Impact: 3-6x on the FIM
    walk and a real cut to quick-scan latency. Needs `list_add` / `proctable_add`
    made thread-safe.
21. **YARA engine to replace substring IOC.** (coverage #11, `ioc.c`) Real rule
    conditions, hex and wildcard patterns. Effort L. Highest detection-quality
    multiplier across file scan and later memory scan.
22. **AMSI / ETW integrity check.** (coverage #12, T1562.001) Read
    `amsi.dll!AmsiScanBuffer` and `ntdll!EtwEventWrite` prologues in each process
    and compare against the on-disk image; a patched prologue is tamper. New
    rules `EVADE.AMSI_PATCH` / `EVADE.ETW_PATCH`. Memory-based, so it survives
    packing. Effort M-L.
23. **Memory scanning for injected code and process hollowing.** (coverage
    #13/#14, T1055) The RWX walk flags protection but never reads the bytes; read
    flagged private regions and scan for shellcode / reflective-PE `MZ` headers,
    and compare module in-memory headers against the on-disk file. Effort L. This
    is the structural answer to "IAT heuristics are defeated by packing."
24. **Authenticate the FIM baseline.** (security L3, `scan_integrity.c`) MAC the
    baseline with a key outside `%ProgramData%`, or warn when the baseline file's
    ACL is user-writable, so a tampered baseline cannot silently shrink the
    monitored scope. Effort M.
25. **v2: signed kernel driver.** Kernel cross-view and a real-time minifilter,
    the only honest way to see a kernel rootkit and to block in real time.
    Effort XL. Explicitly out of scope for the user-mode tool; roadmap only.

## Suggested sequencing

Do Phase 1 as one security release (it is all correctness and safety, low risk
of regression with the prior test pass). Ship Phase 2 next; it is mostly small
diffs that reuse code that already exists and gives the biggest detection jump
per line. Land Phase 3 before Phase 4, because caching `pe_analyze` and the
process prologue is what makes the new credential-access handle walks affordable
to run on every scan. Phase 5 is a roadmap, not a sprint.

## Cross-cutting note to put in the report footer

Every IAT-based heuristic (the keylogger import scan, file SUSPICIOUS_CAPS, the
process-injection flags) is statically defeated by packing: a packed binary
exposes no imports, so the capability flags come back empty and those rules go
quiet. This is the structural reason memory scanning (item 23) matters more than
adding more import-based rules, and it belongs next to the existing
kernel-rootkit honesty caveat in the tool's output.
