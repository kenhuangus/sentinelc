# SentinelC Roadmap And Productization Plan

This document reflects the current codebase after the July 2026 hardening pass.
Several items that older drafts called "v2" are now implemented in the user-mode
scanner and should not be presented as future work.

## Current Product Shape

SentinelC is an on-demand, transparent Windows triage and response tool:

- Native C scanner with no cloud dependency.
- User-mode malware, persistence, network, keylogger/spyware, rootkit-style
  cross-view, credential-access, memory-injection, and AMSI/ETW tamper checks.
- Offline-like VSS hunting without rebooting.
- Merkle FIM baseline/check with authenticated baselines and full content
  rehashing.
- Fleet Console with protected read APIs, per-host ingest tokens, and HTTPS-only
  remote upload helpers.
- Endpoint installer that runs scheduled scans as SYSTEM after one install-time
  elevation.
- Codex skill/plugin packaging for guided incident-response workflows.

## What Still Belongs In v2

1. **Path canonicalization cleanup.**
   Replace remaining substring-style path classification with canonical,
   segment-aware Windows path checks.

2. **Real XML parsing for scheduled tasks.**
   Move task parsing to MSXML/COM or a robust parser so comments, CDATA,
   namespaces, attributes, and `ComHandler` actions are handled consistently.

3. **Persistent caches and performance engineering.**
   Persist signature results across runs, cache PE analysis by file identity, and
   parallelize FIM hashing without weakening integrity semantics.

4. **YARA maturity.**
   Either embed libyara or publish a documented supported subset for
   `yara_lite.c` with tests.

5. **Signed kernel driver.**
   A driver is still the only honest route to kernel-vantage rootkit visibility
   and real-time blocking. It requires WDK/MSVC, EV/attestation signing, a driver
   update model, and a much larger testing burden.

## Productization Must-Haves

1. **Code-sign the binary and installer.**
   Unsigned admin tools will be distrusted and may be blocked by SmartScreen or
   AV reputation systems.

2. **Release channel and update story.**
   Security tools need versioned releases, update checks, and a rollback plan.

3. **Operator report.**
   Add a clean HTML/PDF report with findings, evidence, severity, limitations,
   and response actions. This is what an IR technician attaches to a ticket.

4. **Fleet deployment guidance.**
   The current Fleet Console is functional. Production deployments need TLS in
   front of it, token rotation, backup guidance for `data/`, and clear endpoint
   enrollment/de-enrollment steps.

5. **Support and liability boundaries.**
   Preserve the honest scope: SentinelC is a transparent triage and response
   tool, not a full EDR replacement. Keep dry-run defaults, confirmation gates,
   audit logs, and limitation messaging prominent.

## Positioning

Do not sell SentinelC as a cheaper Defender or CrowdStrike. Those products win
on cloud reputation, managed telemetry, kernel agents, and scale. SentinelC's
strongest lane is:

- Fast on-demand host triage.
- Explainable evidence for each finding.
- Local-only operation when needed.
- Open, inspectable rules and source.
- Useful IR workflows that can be packaged as a CLI, endpoint scheduled task,
  and fleet dashboard.

Recommended business model remains open-core: keep the scanner transparent and
sell fleet management, polished reporting, release support, and incident-response
workflow help.

## Suggested Next Sequence

1. Finish path canonicalization and scheduled-task XML parsing.
2. Add persistent signature/PE caches and profile the full scan again.
3. Package signed releases and installer builds.
4. Harden Fleet Console deployment: TLS reverse-proxy recipes, host token
   rotation, and enrollment docs.
5. Treat kernel-driver work as a funded milestone, not a sprint.
