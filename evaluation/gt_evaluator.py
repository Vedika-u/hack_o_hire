# evaluation/gt_evaluator.py
"""
ACT AWARE — Ground Truth Evaluator
Evaluates system accuracy against the hackathon-provided GT labels.

GT Label Rules (from dataset):
  GT_BRUTE          → MUST raise HIGH/CRITICAL alert (23 failed logins, under-labeled LOW)
  GT_SINGLE         → MUST suppress/downgrade (1 login fail, over-labeled CRITICAL → benign)
  GT_BACKUP_1       → MUST suppress (legitimate backup job, svc_backup user)
  GT_BACKUP_DUP     → MUST deduplicate (exact duplicate of GT_BACKUP_1)
  GT_BACKUP_CONFLICT_HIGH → MUST suppress as FP (legit nightly backup mislabeled HIGH)
  GT_VSS_A          → MUST raise CRITICAL (VSS delete, severity=UNKNOWN → needs inference)
  GT_VSS_B          → MUST raise HIGH (VSS delete, user=anita approved? → still suspicious)
  GT_VSS_C          → MUST raise CRITICAL (VSS delete, conflicting labels → take worst case)
  GT_LSASS          → MUST raise CRITICAL (lsass dump via comsvcs.dll/MiniDump)
  GT_PUNY_DNS       → MUST raise HIGH (punycode domain = phishing/C2)
  GT_PUNY_CONN      → MUST raise HIGH (punycode connection = C2 beacon)
  GT_BAD_TS         → MUST dead-letter (impossible timestamp 25:61:00Z)
  GT_WHOAMI         → MUST suppress as FP (whoami.exe = benign admin activity, mislabeled HIGH)
  MiniDump attempt? → MUST raise CRITICAL (PROC_OPEN on lsass.exe = credential dump)
"""

import json
import os
from typing import Dict, List, Tuple, Any

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


# === GROUND TRUTH SPECIFICATION ===
GT_RULES = {
    "GT_BRUTE": {
        "expected_action": "ALERT",
        "expected_severity": "HIGH",
        "reason": "23 failed logins = brute force, despite LOW label in raw data"
    },
    "GT_SINGLE": {
        "expected_action": "SUPPRESS",
        "expected_severity": None,
        "reason": "Only 1 login fail = benign, mislabeled CRITICAL (over-labeled noise)"
    },
    "GT_BACKUP_1": {
        "expected_action": "SUPPRESS",
        "expected_severity": None,
        "reason": "Legitimate backup job by svc_backup to FILESRV-02 — known benign"
    },
    "GT_BACKUP_DUP": {
        "expected_action": "DEDUPLICATE",
        "expected_severity": None,
        "reason": "Exact duplicate of GT_BACKUP_1 — must be deduplicated"
    },
    "GT_BACKUP_CONFLICT_HIGH": {
        "expected_action": "SUPPRESS",
        "expected_severity": None,
        "reason": "Legit nightly backup mislabeled HIGH — FP suppression required"
    },
    "GT_VSS_A": {
        "expected_action": "ALERT",
        "expected_severity": "CRITICAL",
        "reason": "VSS deletion = ransomware pre-stage, severity=UNKNOWN must be inferred CRITICAL"
    },
    "GT_VSS_B": {
        "expected_action": "ALERT",
        "expected_severity": "HIGH",
        "reason": "VSS delete by anita (unapproved), conflicting labels → HIGH"
    },
    "GT_VSS_C": {
        "expected_action": "ALERT",
        "expected_severity": "CRITICAL",
        "reason": "VSS delete with conflicting labels → worst-case = CRITICAL"
    },
    "GT_LSASS": {
        "expected_action": "ALERT",
        "expected_severity": "CRITICAL",
        "reason": "comsvcs.dll MiniDump on lsass = credential dump, despite LOW label"
    },
    "GT_PUNY_DNS": {
        "expected_action": "ALERT",
        "expected_severity": "HIGH",
        "reason": "Punycode lookalike domain xn--barclays-security-1ve.com = phishing/C2"
    },
    "GT_PUNY_CONN": {
        "expected_action": "ALERT",
        "expected_severity": "HIGH",
        "reason": "Network connection to punycode C2 domain = beacon"
    },
    "GT_BAD_TS": {
        "expected_action": "DEAD_LETTER",
        "expected_severity": None,
        "reason": "Impossible timestamp (25:61:00Z) must be quarantined"
    },
    "GT_WHOAMI": {
        "expected_action": "SUPPRESS",
        "expected_severity": None,
        "reason": "whoami.exe is benign admin recon, mislabeled HIGH — FP"
    },
    "MiniDump attempt?": {
        "expected_action": "ALERT",
        "expected_severity": "CRITICAL",
        "reason": "PROC_OPEN on lsass.exe = credential dump attempt"
    },
}


class GTEvaluator:
    def __init__(self):
        self.results: List[Dict] = []

    def evaluate(
        self,
        gt_label: str,
        system_action: str,      # "ALERT", "SUPPRESS", "DEDUPLICATE", "DEAD_LETTER"
        system_severity: str = None,  # "CRITICAL", "HIGH", "MEDIUM", "LOW", None
        notes: str = ""
    ) -> Dict[str, Any]:
        """
        Evaluate a single GT event against system output.
        Returns score dict with correct/partial/wrong.
        """
        rule = GT_RULES.get(gt_label)
        if not rule:
            return {"gt_label": gt_label, "result": "UNKNOWN_GT", "score": 0}

        expected_action = rule["expected_action"]
        expected_sev = rule["expected_severity"]

        action_correct = (system_action == expected_action)

        if not action_correct:
            score = 0
            result = "WRONG"
        elif expected_sev is None:
            # No severity expected (suppress/dedup/dead-letter)
            score = 1.0
            result = "CORRECT"
        else:
            # Check severity match
            sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, None: 0}
            exp_val = sev_map.get(expected_sev, 0)
            got_val = sev_map.get(str(system_severity).upper() if system_severity else None, 0)
            if got_val >= exp_val:
                score = 1.0
                result = "CORRECT"
            elif got_val == exp_val - 1:
                score = 0.5
                result = "PARTIAL"
            else:
                score = 0.0
                result = "WRONG"

        record = {
            "gt_label": gt_label,
            "expected_action": expected_action,
            "expected_severity": expected_sev,
            "system_action": system_action,
            "system_severity": system_severity,
            "result": result,
            "score": score,
            "reason": rule["reason"],
            "notes": notes,
        }
        self.results.append(record)
        return record

    def score_all(self) -> Dict[str, Any]:
        total = len(self.results)
        if total == 0:
            return {"accuracy": 0.0, "total": 0}
        correct = sum(1 for r in self.results if r["result"] == "CORRECT")
        partial = sum(1 for r in self.results if r["result"] == "PARTIAL")
        wrong = sum(1 for r in self.results if r["result"] == "WRONG")
        score = sum(r["score"] for r in self.results)
        accuracy = round(score / total * 100, 1)
        return {
            "accuracy": accuracy,
            "total": total,
            "correct": correct,
            "partial": partial,
            "wrong": wrong,
            "raw_score": round(score, 2),
            "results": self.results
        }

    def print_report(self):
        summary = self.score_all()
        print("\n" + "=" * 70)
        print("  GT EVALUATION REPORT — ACT AWARE")
        print("=" * 70)
        print(f"  ACCURACY : {summary['accuracy']}%")
        print(f"  CORRECT  : {summary['correct']}/{summary['total']}")
        print(f"  PARTIAL  : {summary['partial']}/{summary['total']}")
        print(f"  WRONG    : {summary['wrong']}/{summary['total']}")
        print("=" * 70)
        print(f"\n  {'GT Label':<30} {'Expected':<12} {'Got':<12} {'Result'}")
        print("  " + "-" * 65)
        for r in self.results:
            exp = r['expected_action'] + ("/" + r['expected_severity'] if r['expected_severity'] else "")
            got = r['system_action'] + ("/" + str(r['system_severity']) if r['system_severity'] else "")
            print(f"  {r['gt_label']:<30} {exp:<12} {got:<12} {r['result']}")
        print("=" * 70)


gt_evaluator = GTEvaluator()
