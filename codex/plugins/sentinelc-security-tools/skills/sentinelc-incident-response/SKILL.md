---
name: sentinelc-incident-response
description: Run SentinelC Windows malware, spyware, keylogger, rootkit, persistence, Defender tamper, offline-like VSS, Codex CLI agent triage, and cleanup-verification workflows. Use when the user asks to run SentinelC, analyze SentinelC JSON findings, ask Codex to investigate findings, investigate malware leads, remove risky Defender exclusions, disable unwanted persistence, quarantine suspicious files, or verify a cleanup.
---

# SentinelC Incident Response

Use this skill to run SentinelC safely, turn findings into an action plan, perform evidence-preserving cleanup, and verify the system afterward.

## Safety Contract

- Preserve evidence before changes: export relevant registry keys, save process inventory, hash files, and copy suspicious artifacts.
- Prefer quarantine or disable over delete. Do not remove drivers, services, or files from system locations without strong evidence and a recovery path.
- Treat broad Defender exclusions, unsigned/invalid autoruns, hidden processes, suspicious drivers, encoded PowerShell, injected memory, and YARA hits as priority leads.
- Treat signed OEM utilities, Store app reparse points, developer tooling, and updater tasks as review items unless another signal confirms risk.
- Never hardcode host-specific paths into reusable artifacts. Ask the user for a repo root, executable path, output directory, or target list when needed.
- After any cleanup, run SentinelC again and compare high/critical findings.

## Workflow

1. Locate SentinelC.
   - If the user is in the SentinelC repo, use that repo.
   - Otherwise ask for `-RepoRoot` or `-ExePath`.
   - Build first if `build/sentinelc.exe` is missing and `build.ps1` is present.

2. Run an elevated scan.
   - Use `scripts/run-sentinelc-scan.ps1`.
   - Prefer `-Mode offline-like -OfflinePasses 1` for cleanup verification.
   - Use `-Mode full -Deep -WatchSeconds 30` when hunting live process/network behavior.

3. Parse findings.
   - Use `scripts/parse-sentinelc-findings.py`.
   - Read `references/rule-action-map.md` for rule-specific priority and action guidance.

4. Optionally ask Codex CLI for an agentic analyst plan.
   - Use `scripts/invoke-codex-triage.ps1` with `-ScanJson` for an existing report or with `-RepoRoot` to run a scan first.
   - Use `-DryRun` first when reviewing what evidence will be sent to the configured Codex provider.
   - Codex must run read-only and ephemeral; treat its output as analyst guidance, not authorization to mutate the host.

5. Investigate before action.
   - Confirm live path, signature, hash, parent process, service start mode, startup entry, and listener state.
   - Decode or attribute encoded PowerShell before stopping it.
   - For YARA hits in non-executable files, locate embedded `MZ`/`PE` offsets and hash the embedded blob.

6. Clean safely.
   - Use `scripts/safe-cleanup-template.ps1` only with explicit target lists.
   - Remove broad Defender exclusions when confirmed.
   - Disable unwanted startup values or services instead of deleting applications.
   - Quarantine suspicious files only with hash guards when possible.

7. Verify.
   - Use `scripts/verify-sentinelc-cleanup.ps1` or rerun the same scan manually.
   - Report before/after counts, remaining high/critical items, and exact artifacts changed.

## Scripts

- `scripts/run-sentinelc-scan.ps1`: run SentinelC, optionally elevate, and write JSON/stderr/status files.
- `scripts/parse-sentinelc-findings.py`: summarize SentinelC JSON and produce a Markdown action plan.
- `scripts/invoke-codex-triage.ps1`: compact and redact SentinelC JSON, call Codex CLI in read-only ephemeral mode, and render an agent analyst plan.
- `scripts/safe-cleanup-template.ps1`: parameterized cleanup wrapper with evidence capture.
- `scripts/verify-sentinelc-cleanup.ps1`: run a verification scan and parse the result.

## References

- `references/rule-action-map.md`: rule priorities, likely false positives, and safe actions.
- `references/destructive-action-policy.md`: cleanup guardrails and rollback expectations.
- `schemas/agent-plan.schema.json`: required structured output for Codex CLI triage.
