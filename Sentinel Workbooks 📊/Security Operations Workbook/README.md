# 📊 Endpoint Security Workbook — How These Fit Together

Three sections inside one workbook. They're not alternatives to each other — together they cover the full loop of prevention, detection, and hunting for the endpoint fleet.

---

## 🗺️ The three at a glance

| Section | Mode | Question it answers | Trigger |
| --- | --- | --- | --- |
| 🛡️ **ASR Detections** | Passive, continuous | *What did Defender block automatically?* | Policy fires on its own |
| 🦠 **AV Detections** | Passive, continuous | *What did Defender catch — and did it clean up?* | Signature fires on its own |
| 🎯 **Endpoint Hunts** | Active, scheduled | *What's happening that nothing caught yet?* | An analyst runs the hunt |

---

## 🔄 How they relate

```
🛡️ ASR Detections  ⎫
                     ⎬  passive signal — confirms protection is working
🦠 AV Detections    ⎭

🎯 Endpoint Hunts   ─  active search — finds what policy and signature can't
                        (technique-level behavior, not a known bad pattern)

                All three converge here:
                        ↓
         A device shows up repeatedly, or a hunt hit
         looks worth escalating
                        ↓
        🔍 Incident Response Workbook (Device Compromise Triage)
```

ASR and AV don't depend on each other or on Endpoint Hunts — they run in parallel, watching different failure modes. Endpoint Hunts is the odd one out: it's the only section here that requires a person to actively go looking, because it's built to catch what the other two structurally can't — behavior with no signature and no policy match.

---

## 🛡️ ASR Detections

**Purpose: confirm what attack surface reduction blocked.**

Native ASR rule firings across the fleet — a signal source, not a triage queue. A spike in one rule usually means either a new attack pattern hitting multiple devices, or a legitimate tool that needs an exception carved out, not an active incident on its own.

> 💡 Watch for the same rule firing on the same device repeatedly — that's a stronger signal than a one-off hit anywhere else.

---

## 🦠 AV Detections

**Purpose: confirm what antivirus caught — and whether it actually stopped it.**

Native AV detections across the fleet, with particular attention to remediation status. The gap that matters most here isn't "was something detected" — it's "was it detected *and* successfully remediated." An unremediated detection is a live problem, not a closed one.

> 💡 A detection with `NotRemediated` status is worth more attention than three clean removals — it means the threat may still be present.

---

## 🎯 Endpoint Hunts

**Purpose: find what ASR and AV structurally can't.**

Proactive, technique-level hunting — evasion, staging, unapproved tooling, rare persistence — grouped by cadence rather than run as one flat list. Daily hunts need same-day eyes; weekly and monthly hunts cover slower-moving or more expensive queries.

Unlike the other two sections, nothing here fires on its own. It's only as current as the last time someone ran it.

> 💡 If a hunt hasn't been run in its expected cadence window, treat that gap itself as a coverage risk, not just an empty result.

---

## ⚖️ Passive vs. active — why both are necessary

| | ASR / AV | Endpoint Hunts |
| --- | --- | --- |
| Trigger | Automatic — policy or signature match | Manual — analyst runs the query |
| Cadence | Continuous, real-time | Daily / weekly / monthly |
| Coverage | Known techniques, policy-defined | Technique-level behavior, no signature required |
| Confidence | High — already confirmed by the engine | Variable — candidate for investigation |
| Blind spot | Anything with no matching rule or signature | Nothing runs itself — depends on hunt cadence being kept |

Neither replaces the other. ASR and AV tell you protection is working; Endpoint Hunts tells you what protection was never going to catch in the first place.

---

## 🧭 Quick reference — where do I look?

| Situation | Section |
| --- | --- |
| Morning check, nothing specific | 🎯 Endpoint Hunts (daily) |
| Checking whether protection is firing fleet-wide | 🛡️ ASR Detections / 🦠 AV Detections |
| A detection came back unremediated | 🦠 AV Detections → escalate if unresolved |
| Same ASR rule firing across multiple devices | 🛡️ ASR Detections → check for new campaign vs. FP |
| A hunt turns up something worth digging into | 🔍 Incident Response Workbook |

---

## 📌 Notes

Exclusion lists and benign-parent filters are environment-specific — keep them current as new sanctioned tooling gets deployed, or hunts will drown in known-good noise.

This workbook surfaces activity for human review; it doesn't take action on its own. Pair anything high-fidelity here with a scheduled analytics rule if it should page someone instead of waiting to be glanced at.