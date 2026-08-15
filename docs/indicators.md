# Detection Engine Reference

BinaryLens's detection engine (`binarylens/analysis/correlation.py` and
`binarylens/analysis/indicators/`) is built around one core principle:

```text
API detected → suspicious → +1 risk        ✗ NOT this
```

```text
Binary characteristics → Capabilities → Anomalies → Correlated
indicators → Contextual findings → Severity        ✓ this
```

An individual API almost never means anything on its own. `OpenProcess`,
`VirtualAlloc`, `GetProcAddress`, `RegSetValueExW` — all of these show up
constantly in completely ordinary software (installers, debuggers,
runtimes, browsers). The engine only produces a non-informational
**Finding** when it sees a *correlated pattern* of evidence, and every
finding explains exactly which APIs or characteristics it's based on.

## Capabilities vs. Findings

- **Capabilities** (`[Capabilities]` in the terminal report,
  `analysis.capabilities` in JSON) describe what the binary appears able
  to do, grouped by category (Process Management, Memory Management,
  Registry, Networking, ...). Capabilities never carry a severity and
  never contribute to a risk score by themselves.

- **Findings** (`[Findings]`, `analysis.findings` in JSON) are the
  engine's actual output: specific, evidence-backed observations, each
  with a severity (`INFO` / `LOW` / `MEDIUM` / `HIGH`), a plain-language
  description, and the exact evidence that produced it.

## Rule modules

| Module | What it correlates |
|---|---|
| `indicators/api_categories.py` | Classifies every recognized imported API into one of 13 capability categories. Never produces a Finding by itself. |
| `indicators/injection.py` | Process-handle + remote-memory-allocation + remote-memory-write + remote-thread APIs. 3 of 4 stages → MEDIUM "Possible process injection pattern"; all 4 → HIGH "Strong process injection pattern". Fewer than 3 stages → no finding, just capability context. |
| `indicators/anti_debug.py` | Debugger-detection APIs only (never plain timing APIs like `QueryPerformanceCounter`/`GetTickCount`). One API → LOW; more than one distinct API → MEDIUM "Multiple anti-debugging indicators detected". |
| `indicators/persistence.py` | Registry-write APIs *combined with* service-management APIs → LOW "Possible persistence-related capability". Either alone → capability only. |
| `indicators/sections.py` | Classifies every section name (Known/Common, Known Toolchain, Known Installer, Potentially Suspicious, Unknown) and only raises a finding when a section is *both* unrecognized/packer-named *and* structurally unusual (writable+executable, or an odd virtual/raw size ratio, or high entropy). |
| `indicators/packing.py` | Combines high-entropy sections, a very small import table, and packer-associated section names. A single high-entropy section alone → INFO only. Two or more of the three signals together → MEDIUM "Possible packing indicators". |
| `indicators/overlay.py` | Reports overlay presence/size/ratio as INFO context always. A large overlay in a binary with recognized installer characteristics is described as consistent with bundled installer data rather than flagged as an anomaly. |
| `indicators/installers.py` | Recognizes WiX Burn, NSIS, Inno Setup, MSI, InstallShield, and similar packaging frameworks from section names and embedded strings. Feeds context into the section and overlay rules above so ordinary installer characteristics aren't misclassified as anomalies. |

`correlation.py` orchestrates all of the above, plus a small, curated set
of low-noise `INFO`-level capability notes (dynamic linking, process
management, registry) that only appear when nothing more specific
already covers that category — so a binary that *does* trigger, say, the
persistence rule doesn't also get a redundant generic registry note.

## Severity model

| Severity | Meaning |
|---|---|
| `INFO` | Purely contextual observation; not evidence of anything unusual. |
| `LOW` | A single weak indicator with limited corroboration. |
| `MEDIUM` | Multiple correlated indicators, or a partial match on a well-known behavioral pattern. |
| `HIGH` | A strong, fully-matched behavioral pattern (e.g. the complete process injection chain). |

There is no numeric "risk score" and no malware probability. The JSON
report's `analysis.severity_summary` is a count of findings per severity
level — how many rules fired, not a weighted verdict — and
`analysis.assessment_note` is a short, deliberately hedged qualitative
note (never a percentage, never the word "malware", never a confident
verdict).

## Design principles

1. **No verdicts.** No rule ever concludes "malicious" or "malware", and
   no finding text claims certainty it doesn't have.
2. **Every non-trivial finding explains its evidence.** The JSON and
   terminal output always show exactly which APIs or characteristics
   produced a finding, plus a confidence label.
3. **Context matters.** Recognized installer/packaging characteristics
   soften how overlay size and section names are interpreted, without
   ever being hardcoded to a specific filename or vendor.
4. **Fewer, higher-quality findings over many noisy ones.** A capability
   inventory of 20 APIs across 6 categories is normal and expected in
   real-world software; the engine is built to not turn that inventory
   into 20 warnings.
