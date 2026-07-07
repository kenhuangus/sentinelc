# SentinelC Agentic Codex CLI Provider Spec

Status: corrected after two spec review rounds
Requested filename: `agent-sepc.md`

## 1. Investigation Summary

SentinelC already has the right local building blocks for an AI-assisted workflow:

- `build/sentinelc.exe` emits a structured JSON report with `findings`, `summary`, `limitations`, and `cache`.
- `codex/skills/sentinelc-incident-response/scripts/run-sentinelc-scan.ps1` runs a scan and writes `sentinelc.json`, stderr, and status artifacts.
- `codex/skills/sentinelc-incident-response/scripts/parse-sentinelc-findings.py` turns JSON findings into a deterministic action plan.
- `codex/skills/sentinelc-incident-response/scripts/safe-cleanup-template.ps1` performs evidence-preserving cleanup only from explicit target lists.
- `codex/skills/sentinelc-incident-response/references/destructive-action-policy.md` defines the safety contract for any cleanup.
- Local Codex CLI version `0.142.4` supports non-interactive `codex exec`, `--cd`, `--sandbox read-only`, `--ask-for-approval never`, `--output-schema`, and `--output-last-message`.

The missing feature is a guarded AI analyst layer. SentinelC should be able to send a compact scan packet to Codex CLI, receive a structured investigation and cleanup plan, and keep all destructive activity outside the model path.

## 2. Goals

1. Add agentic triage behavior for SentinelC reports using Codex CLI as the AI provider.
2. Keep SentinelC's scanner and responder safety model unchanged.
3. Produce reviewable artifacts: compact input, prompt, Codex raw result, Markdown plan, and status.
4. Support both workflows:
   - Analyze an existing SentinelC JSON report.
   - Run SentinelC first, then analyze the new report.
5. Make the provider call non-interactive and read-only by default.
6. Keep implementation reusable inside both the standalone Codex skill and the plugin bundle.

## 3. Non-Goals

- Do not embed an AI provider inside the native C scanner.
- Do not allow Codex to run cleanup commands or mutate the host.
- Do not use `--dangerously-bypass-approvals-and-sandbox`.
- Do not send raw secrets, bearer tokens, private keys, or credential material to the model.
- Do not pretend this replaces analyst judgment, Defender Offline, EDR, or kernel-level rootkit inspection.

## 4. Threat Model

The agent workflow handles hostile evidence. Finding fields can include attacker-controlled paths, service names, scheduled-task arguments, command lines, and registry values. The AI provider must treat those fields as data, not instructions.

Primary risks:

- Prompt injection from findings, file paths, command lines, or evidence strings.
- Over-trusting model cleanup recommendations.
- Accidentally sending secrets or local-only operational data to the model.
- Letting the model mutate the workstation.
- Producing an action plan that looks authoritative while missing SentinelC limitations.

Required controls:

- The prompt must explicitly state that scan fields are untrusted evidence.
- Codex must run with `--sandbox read-only` and `--ask-for-approval never`.
- The script must never pass `--dangerously-bypass-approvals-and-sandbox`.
- The script must produce plans only; cleanup remains a separate human-approved script.
- The input packet must cap findings and include omission counts.
- The output schema must require limitations, preconditions, rollback, and verification sections.

## 5. User Experience

Add a script:

```powershell
codex/skills/sentinelc-incident-response/scripts/invoke-codex-triage.ps1
```

Common usage:

```powershell
# Analyze an existing scan
powershell -ExecutionPolicy Bypass -File codex/skills/sentinelc-incident-response/scripts/invoke-codex-triage.ps1 `
  -ScanJson .\scan\sentinelc.json

# Run SentinelC first, then ask Codex for an analyst plan
powershell -ExecutionPolicy Bypass -File codex/skills/sentinelc-incident-response/scripts/invoke-codex-triage.ps1 `
  -RepoRoot . -Mode offline-like -OfflinePasses 1

# Prepare prompt artifacts without calling Codex
powershell -ExecutionPolicy Bypass -File codex/skills/sentinelc-incident-response/scripts/invoke-codex-triage.ps1 `
  -ScanJson .\scan\sentinelc.json -DryRun
```

The script writes an output directory such as `sentinelc-agent-20260707-120000` containing:

- `agent-input.json`: compact, capped SentinelC finding packet.
- `agent-prompt.md`: exact prompt sent to Codex.
- `agent-plan.schema.json`: schema used for Codex's final response.
- `agent-plan.json`: structured Codex output.
- `agent-plan.md`: rendered human-readable plan.
- `codex.stdout.txt`: provider stdout.
- `codex.stderr.txt`: provider stderr.
- `status.txt`: command status and artifact paths.

## 6. Provider Contract

The first implementation uses the installed Codex CLI:

```powershell
codex `
  --sandbox read-only `
  --ask-for-approval never `
  exec `
  --cd <repo-root> `
  --ephemeral `
  --color never `
  --output-schema <agent-plan.schema.json> `
  --output-last-message <agent-plan.json> `
  -
```

Optional:

- `-Model <model>` passes `--model <model>` to Codex CLI.
- `-CodexPath <path>` allows a non-default Codex executable.
- `-MaxFindings <n>` caps the number of findings sent to Codex.
- `-MaxEvidenceChars <n>` caps each evidence string.
- `-NoElevate` passes through to scan execution when the script runs SentinelC first.
- `-DryRun` writes prompt artifacts and skips the provider call.

Provider rules:

- Do not enable web search by default.
- Do not pass user or project secrets as environment variables.
- Redact token-like values from prompt artifacts before invoking Codex. Local paths, registry keys, service names, process names, and findings are allowed because they are core triage evidence, but the script must not hardcode them into reusable repo files.
- Do not run with write-capable sandbox settings.
- Use `--ephemeral` so sensitive incident prompts are not intentionally persisted in Codex session history.
- Use `--color never` for deterministic provider logs.
- Treat a non-zero Codex exit as a failed provider call but preserve artifacts.
- The provider output must match the JSON schema before rendering the Markdown plan.

## 7. Agent Input Contract

`agent-input.json` contains:

- `source_report`: absolute path to the local SentinelC report.
- `generated_at`: current timestamp.
- `summary`: SentinelC summary object when present.
- `cache`: SentinelC cache object when present.
- `limitations`: report limitations split into lines.
- `rule_counts`: counts by rule id.
- `finding_count`: original finding count.
- `included_finding_count`: number of findings sent to Codex.
- `omitted_finding_count`: number omitted because of cap.
- `findings`: capped list sorted by severity and confidence.

Each included finding contains only:

- `rule`
- `severity`
- `confidence`
- `pid`
- `target`
- `title`
- `evidence`
- `recommended`

The script must cap evidence strings and finding count to avoid huge prompts.

The script must redact common secret patterns before writing `agent-input.json` and `agent-prompt.md`, including:

- Authorization bearer tokens
- API key assignments
- secret assignments
- password assignments
- PEM private-key blocks
- GitHub tokens beginning with `ghp_`
- AWS access keys beginning with `AKIA`

## 8. Agent Output Contract

Codex must return JSON with:

- `overall_assessment`
- `risk_score`
- `executive_summary`
- `priority_findings`
- `investigation_plan`
- `cleanup_plan`
- `verification_plan`
- `do_not_touch`
- `limitations`
- `provider_notes`

Each cleanup item must include:

- `action_type`
- `target`
- `reason`
- `preconditions`
- `rollback`
- `command_hint`
- `requires_human_confirmation`

Allowed `action_type` values:

- `review`
- `collect_evidence`
- `remove_defender_exclusion`
- `disable_persistence`
- `disable_service`
- `quarantine_file`
- `kill_or_suspend_process`
- `update_ioc`
- `no_action`

The Markdown renderer must not turn `command_hint` into an automatic script. It is only analyst guidance.

## 9. Safety Policy

The model may recommend investigation and cleanup, but all cleanup remains human-gated.

The script must:

- Refuse to run if Codex is missing unless `-DryRun` is used.
- Warn in the status artifact that Codex CLI may send prompt content to the configured AI provider.
- Never call cleanup scripts.
- Never invoke `sentinelc.exe` with responder flags.
- Never pass `--interactive`, `--kill`, `--suspend`, `--disable-service`, `--quarantine`, `--yes`, or `--force-critical`.
- Never use Codex CLI write-capable sandboxes for this workflow, even if the caller asks for automatic cleanup.
- Preserve existing SentinelC limitations in the AI prompt and output.

## 10. Implementation Plan

1. Add `agent-plan.schema.json` under the skill package.
2. Add `invoke-codex-triage.ps1` under the skill package.
3. Duplicate those artifacts into the plugin bundle.
4. Update both `SKILL.md` files to mention the agent workflow.
5. Update plugin metadata prompt examples to include Codex triage.
6. Update `.gitignore` for local `sentinelc-agent-*` output directories.
7. Test:
   - PowerShell parser checks for new and existing scripts.
   - JSON schema parses.
   - Dry-run prompt generation against a small sample report.
   - Native C build still passes.
   - Existing read-only scanner smoke still emits valid JSON.

## 11. Acceptance Criteria

- `agent-sepc.md` includes two completed review rounds.
- New script can generate prompt artifacts with `-DryRun`.
- New script refuses missing Codex on real provider calls.
- New script invokes Codex only with read-only/non-interactive provider settings.
- New script adds `--ephemeral` and `--color never` to provider calls.
- Output schema is valid JSON.
- Both standalone skill and plugin bundle contain the agent workflow.
- Build and script syntax tests pass.

## 12. Spec Review Log

### Round 1

Findings:

- The first draft said not to send "local host configuration," but SentinelC findings necessarily contain local paths, registry keys, services, and process details. That would make the feature unusable.
- The first draft did not name redaction controls or prompt-size controls as script parameters.
- The first draft did not explicitly forbid write-capable Codex sandboxes when the caller asks for automatic cleanup.

Corrections applied:

- Replaced the broad host-configuration ban with a precise secret and credential-material ban.
- Added default redaction requirements for token-like strings and private-key material.
- Added `-MaxFindings`, `-MaxEvidenceChars`, and `-NoElevate` to the provider wrapper contract.
- Added an explicit ban on write-capable Codex sandboxes for this workflow.

### Round 2

Findings:

- The reviewed provider command avoided host mutation but did not address Codex session persistence. SentinelC scan reports can include sensitive local paths, process command lines, registry values, and security posture details.
- The reviewed provider command did not force stable, non-colored provider logs, which makes automated status review noisier.

Corrections applied:

- Added `--ephemeral` to the provider command and acceptance criteria.
- Added `--color never` to the provider command and provider rules.
- Left the read-only sandbox and no-approval settings intact.
