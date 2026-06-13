# SentinelC v2 + Productization Plan

Two questions: what does v2 look like technically, and what would it take to sell
this as a product. This doc answers both honestly, including the parts that are
hard or that this machine cannot do.

## Part 1 — What v2 actually is

v2 has one headline feature (a kernel driver) that is design-only on this
machine, and a set of user-mode features that are buildable now with the
existing MinGW toolchain. Build the buildable set first; it delivers most of the
value without the cost and risk of shipping a driver.

### 1a. Buildable now (user-mode, current toolchain) — do these first

1. **In-memory injected-code & process-hollowing scanning.** The single highest
   value. Today the RWX-memory rule flags that suspicious memory *exists* but
   never reads it. v2 reads flagged private/RWX regions and scans for shellcode
   markers and reflective-PE `MZ`/`PE` headers, and compares each module's
   in-memory headers against its on-disk file to catch hollowing. This is the
   structural answer to "every IAT heuristic is defeated by packing": a packed
   loader hides its imports but cannot hide the code it unpacks into memory.
   Effort: L. New rules `MEM.SHELLCODE`, `MEM.REFLECTIVE_PE`, `PROC.HOLLOWED`.
2. **AMSI / ETW tamper detection.** Read `amsi.dll!AmsiScanBuffer` and
   `ntdll!EtwEventWrite` prologues in each process and compare to the clean
   on-disk bytes. A patched prologue is the classic "blind the defender" move
   and is memory-resident, so it survives packing. Effort: M. Rules
   `EVADE.AMSI_PATCH`, `EVADE.ETW_PATCH`.
3. **A real YARA engine.** Replace the substring IOC matcher with compiled rule
   conditions, hex patterns with wildcards, and string sets. Either embed
   libyara or implement a focused subset. This is the feature security buyers
   expect by name. Effort: L.
4. **Authenticated baseline (FIM integrity).** HMAC the Merkle baseline with a
   key stored outside the baseline's directory, and warn when the baseline file
   is writable by non-admins, so an attacker cannot silently shrink the
   monitored set. Effort: M.
5. **Output and integration polish.** NDJSON streaming, a stable JSON schema
   with a version field, Sigma/STIX export, and an exit-code contract for CI.
   This is what makes it embeddable in someone else's pipeline. Effort: M.

### 1b. Design-only here (the kernel driver) — needs WDK + signing

The driver is the only honest way to (a) see a kernel rootkit and (b) block in
real time. It cannot be built or loaded on this machine (no WDK/MSVC; driver
load requires an EV cert + Microsoft attestation signing). v2 ships a design and
a WDK-buildable skeleton, not a working driver, until that toolchain exists.

Design shape:
- A **minifilter** (FltMgr) for real-time file and process callbacks
  (`PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks` to strip dangerous
  handle rights to LSASS, image-load callbacks for unsigned drivers).
- A **kernel cross-view**: walk the kernel's own process/handle/driver lists and
  hand them to the user-mode engine over an IOCTL, so the existing cross-view
  diff gains a vantage point a DKOM rootkit cannot lie to from user mode.
- A thin user-mode/kernel protocol (a single device + versioned IOCTLs) so the
  current scanner becomes the driver's client.
- Honest scope even with a driver: a driver competing with vendor anti-tamper
  and with attackers who also load drivers (BYOVD) is a real arms race; this is
  detection-and-visibility, still not a full EDR.

Cost to actually ship the driver: a Windows Hardware Dev account, an EV code-
signing certificate, WHQL/attestation submission, and a test-signing dev loop.
That is real money and real calendar time, and it is the gate, not the code.

## Part 2 — Selling it as a product

The honest market read first, then the concrete to-do list.

### 2a. Positioning — what it is and is not

It will not win as "a cheaper Defender/CrowdStrike." Those win on cloud
telemetry, ML, and kernel agents, and that race needs capital this does not
have. It can win as a **fast, transparent, on-demand triage and IR tool** for
people who already suspect something and want answers they can read. The buyers
who feel that pain: incident responders, MSP/MSSP technicians, SOC analysts, and
power users doing a "is this box clean" check. Lead with transparency and speed,
not coverage.

### 2b. The must-haves before anyone pays

These are table stakes; without them the tool reads as a hobby project no matter
how good the engine is.

1. **Code-sign the binary.** Today `sentinelc.exe` is unsigned, so SmartScreen
   and other AV flag it on download. An OV or EV code-signing certificate (a few
   hundred dollars a year) is non-negotiable for a security product people run
   as admin. This is the first dollar to spend.
2. **An installer + auto-update.** An MSI/EXE installer, a versioned release
   channel, and an update check. Security tools that cannot update themselves
   are a liability.
3. **A real report, not just console text.** A clean HTML/PDF report with the
   findings, evidence, severity, and a remediation summary. This is what a
   technician hands a client or attaches to a ticket.
4. **A management view for fleets.** The single biggest revenue unlock: run it
   across many machines and roll the JSON up into one dashboard. MSPs buy
   per-endpoint visibility, not a single CLI. Even a thin server that ingests the
   NDJSON and shows a fleet table changes the price point entirely.
5. **Documentation and support.** A docs site, a getting-started that takes
   minutes, and a support channel. Security buyers buy trust and answers.

### 2c. Differentiators worth marketing

- **Transparency:** every rule is readable, every finding cites evidence. No
  black box. This is genuinely rare and worth leading with.
- **Speed:** a full triage in seconds, no agent, no cloud round-trip.
- **The FIM Merkle baseline:** "tell me exactly what executable changed since
  yesterday" is a clean, demoable story.
- **The incident proof:** it found a real infostealer's dropper engine that
  three cleanups and a commercial AV missed. That case study sells.

### 2d. Business model options

- **Open-core.** Keep the engine open (trust + adoption), sell the fleet
  console, reporting, and support. Fits the "transparency" brand best.
- **Commercial license for the CLI** to MSPs/IR shops, per-technician or
  per-endpoint. Simple, but commodity CLIs are hard to defend.
- **IR-engagement tooling.** Sell it bundled with an IR service, where the tool
  is the delivery vehicle and the service is the product.
Recommended: open-core, with the fleet console + reporting + support as the paid
tier. It matches the only real moat here (transparency and speed).

### 2e. The hard truths

- **Liability.** A security product that misses a threat, or kills a legitimate
  process, carries real risk. You need a clear license disclaimer, conservative
  defaults (dry-run already is), and an allowlist story.
- **The trust paradox.** You are asking people to run an admin tool that kills
  processes and quarantines files. Code signing, open source, and a clean track
  record are the only currencies that buy that trust.
- **Support cost.** Every endpoint product generates support load
  disproportionate to its price. Budget for it or scope the buyer narrowly
  (technical users who self-serve).
- **The market is crowded** at the top (EDR) and at the bottom (free AV). The
  open lane is the transparent, fast, IR-grade triage tool for technical
  responders. Stay in that lane.

## Suggested sequence

1. Build the v2 user-mode features in 1a, in order (memory scanning first — it
   is the biggest detection gain and the best demo).
2. Code-sign the binary and stand up an installer + release channel. This is the
   cheapest, highest-leverage productization step.
3. Build the thin fleet console (ingest NDJSON, fleet table). This is the
   revenue unlock.
4. Treat the kernel driver as a funded milestone, not a sprint — it needs the
   WDK toolchain, an EV cert, and Microsoft attestation before a single line of
   it can ship.
