# Arbiter Model — Simple Explanation

## What is the Arbiter?

The Arbiter is a **decision combiner**. It takes the output of two models and decides which one to trust for each alert.

| Model | Role | Strength | Weakness |
|---|---|---|---|
| Random Forest | Supervised classifier | Very accurate (99.7%) | Can be overconfident on ambiguous alerts |
| IsolationForest | Anomaly detector | Independent second opinion | Weaker alone (83.9%) |

Think of it like a **courtroom**:

- The **classifier** is the main judge (experienced, usually right)
- The **anomaly detector** is a witness (less authoritative, but sometimes catches what the judge missed)
- The **arbiter** is the final verdict rule: *"if the judge is unsure AND the witness raises a flag → change the verdict"*

---

## The Decision Rule

```
IF   classifier says BENIGN
AND  anomaly detector says SUSPICIOUS
AND  classifier confidence < 90%
THEN override → assign the most probable ATTACK class
ELSE keep the classifier's original prediction
```

---

## Example 1 — Arbiter overrides (catches a missed attack)

**Alert received:**
```
rule_level        : 5
rule_firedtimes   : 2
data_src_port     : 4444
data_proto        : tcp
data_http_method  : POST
```

**Step 1 — Classifier:**
> "I've seen similar patterns that were benign. My prediction: **BENIGN**"
> Confidence: **71%**

**Step 2 — Anomaly Detector:**
> "Port 4444 with POST over TCP is unusual for normal traffic. I flag this as **SUSPICIOUS**."

**Step 3 — Arbiter applies the rule:**
```
classifier said BENIGN          ✓
anomaly detector flagged it     ✓
confidence (71%) < 90%          ✓
→ ALL THREE conditions met → OVERRIDE
```

**Final decision: WebAttack** ← next most probable class

> Without the arbiter, this attack would have been silently missed.

---

## Example 2 — Arbiter keeps classifier result (high confidence)

**Alert received:**
```
rule_level        : 3
rule_firedtimes   : 120
decoder_name      : web-accesslog
data_http_status  : 200
data_http_method  : GET
```

**Step 1 — Classifier:**
> "This is clearly normal web traffic. My prediction: **BENIGN**"
> Confidence: **97%**

**Step 2 — Anomaly Detector:**
> "I flag this as **SUSPICIOUS**."

**Step 3 — Arbiter applies the rule:**
```
classifier said BENIGN          ✓
anomaly detector flagged it     ✓
confidence (97%) < 90%          ✗  ← condition fails
→ NOT all conditions met → KEEP original prediction
```

**Final decision: BENIGN** ← classifier trusted

> The anomaly detector raised a false alarm. The arbiter ignored it because the classifier was very sure.

---

## Example 3 — Arbiter keeps classifier result (attack already detected)

**Alert received:**
```
rule_level        : 12
rule_groups       : web|accesslog|attack
data_alert_category : Web Application Attack
data_http_method  : GET
```

**Step 1 — Classifier:**
> "This matches known attack signatures. My prediction: **WebAttack**"
> Confidence: **99%**

**Step 2 — Anomaly Detector:**
> "This is indeed suspicious. Flagging as **SUSPICIOUS**."

**Step 3 — Arbiter applies the rule:**
```
classifier said BENIGN          ✗  ← condition fails (it said WebAttack)
→ NOT all conditions met → KEEP original prediction
```

**Final decision: WebAttack** ← classifier trusted, no override needed

> Both models agree. The arbiter has nothing to do.

---

## Example 4 — Arbiter keeps classifier (anomaly detector is calm)

**Alert received:**
```
rule_level        : 4
rule_firedtimes   : 1
data_dns_rrtype   : TXT
data_dstip        : 8.8.8.8
```

**Step 1 — Classifier:**
> "Looks like a DNS exfiltration attempt. My prediction: **Exfiltration**"
> Confidence: **88%**

**Step 2 — Anomaly Detector:**
> "This looks within normal range to me. No flag."

**Step 3 — Arbiter applies the rule:**
```
classifier said BENIGN          ✗  ← condition fails (it said Exfiltration)
→ NOT all conditions met → KEEP original prediction
```

**Final decision: Exfiltration** ← classifier trusted

> The arbiter override only activates when classifier says BENIGN. If it already detected an attack, no override is needed.

---

## Summary of All Cases

| Classifier says | Anomaly flags | Confidence | Arbiter decision |
|---|---|---|---|
| BENIGN | YES | < 90% | **OVERRIDE → attack** |
| BENIGN | YES | ≥ 90% | Keep BENIGN |
| BENIGN | NO | any | Keep BENIGN |
| Attack | YES or NO | any | Keep attack |

---

## Why This Design?

| Reason | Explanation |
|---|---|
| Classifier dominates | It is far more accurate (99.7% vs 83.9%) |
| Anomaly detector is a safety net | It catches edge cases the classifier is uncertain about |
| Confidence threshold (90%) | Avoids flipping correct BENIGN predictions on false alarms |
| Fallback to best attack class | When overriding, picks the most plausible attack, not a random one |

---

## Code Reference

The full logic lives in [`src/arbiter_model.py`](../src/arbiter_model.py), lines 71–82:

```python
suspicious_mask = (
    (classifier_pred == benign_label_id)   # classifier said BENIGN
    & (anomaly_flags == 1)                 # anomaly detector disagrees
    & (classifier_confidence < 0.90)       # classifier is not sure
)

attack_probabilities = classifier_proba.copy()
attack_probabilities[:, benign_label_id] = -1          # exclude BENIGN
fallback_attack = attack_probabilities.argmax(axis=1)  # best attack class
arbiter_pred[suspicious_mask] = fallback_attack[suspicious_mask]
```
