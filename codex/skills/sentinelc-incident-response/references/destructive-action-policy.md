# Destructive Action Policy

Use this policy whenever a SentinelC workflow touches processes, services, registry startup, Defender preferences, or files.

## Required Evidence

- Process: PID, image path, parent PID/name, command line, signature, and network listener state when relevant.
- File: full path, size, timestamps, SHA256, signature status, and a preserved copy before quarantine.
- Registry: export the relevant key before and after mutation.
- Service: capture `Win32_Service` fields before stopping or disabling.
- Scheduled task: export XML before deleting or disabling.
- Defender exclusions: export the exclusions registry key and `Get-MpPreference` output before and after changes.

## Allowed Safer Actions

- Remove broad Defender exclusions.
- Remove or disable user startup entries.
- Stop user applications exposing unexpected listeners.
- Disable unwanted non-critical services.
- Move suspicious non-system files into a quarantine directory.

## Guardrails

- Do not delete files directly. Quarantine with evidence.
- Do not remove boot/system drivers without a rollback plan.
- Do not kill critical Windows processes.
- Do not disable audio, input, network, storage, VPN, or security services solely because they import hook or capture APIs.
- Do not act on one medium finding when signature and vendor context are clean.
- If a target hash does not match the investigated hash, skip mutation and preserve a review copy only.

## Verification

After cleanup:

1. Re-run SentinelC with the same or stronger mode.
2. Confirm removed Defender exclusions are absent.
3. Confirm disabled startup/service entries are absent or disabled.
4. Confirm quarantined files are absent from the original path and present in quarantine.
5. Summarize remaining high/critical findings.
