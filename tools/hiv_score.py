#!/usr/bin/env python3
"""
hiv_score.py — HIV Viral Fitness Scoring System
================================================
Scores an attack engagement target using HIV 'viral fitness' analogy.

HIV viral fitness = the virus's ability to replicate, evade, and persist
in a given host environment. High fitness → full lifecycle. Low fitness → abort.

Web2 equivalent: scores how well the HIV attack framework will work against
a specific target, given its defenses, exposure, and tech stack.

Usage:
    python hiv_score.py                          # interactive mode
    python hiv_score.py --input profile.json     # JSON input mode
    python hiv_score.py --input profile.json --output report.json
"""

import argparse
import json
import sys
import os
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─── SCORING WEIGHTS ─────────────────────────────────────────────────────────

WEIGHTS = {
    "receptor_affinity":   0.25,   # how accessible is the target surface?
    "evasion_capability":  0.20,   # WAF strength vs bypass techniques
    "persistence_options": 0.20,   # how many persistence tiers available?
    "mutation_depth":      0.15,   # payload variation potential
    "cd4_degradability":   0.10,   # how susceptible is detection to noise?
    "lateral_surface":     0.10,   # adjacent infrastructure for budding
}

# ─── THRESHOLDS ──────────────────────────────────────────────────────────────

FULL_LIFECYCLE   = 7.0
SELECTIVE_STAGES = 4.0
# below SELECTIVE_STAGES = ABORT


# ─── STAGE REQUIREMENTS ──────────────────────────────────────────────────────
# Each stage has a minimum score requirement for the relevant factors

STAGE_REQUIREMENTS = {
    "Stage 1: gp120 Recon":            {"receptor_affinity": 3.0},
    "Stage 2: gp41 Initial Access":    {"receptor_affinity": 5.0, "evasion_capability": 4.0},
    "Stage 3: Reverse Transcriptase":  {"mutation_depth": 4.0, "evasion_capability": 3.0},
    "Stage 4: Integration/Persistence":{"persistence_options": 5.0},
    "Stage 5: Cell Hijack":            {"lateral_surface": 4.0, "receptor_affinity": 5.0},
    "Stage 6: Budding":                {"lateral_surface": 6.0},
}


# ─── TOOL RECOMMENDATIONS ────────────────────────────────────────────────────

def recommend_tools(scores: dict) -> list:
    tools = []

    if scores["receptor_affinity"] >= 5:
        tools.append("rat_ghost.py   → browser-fingerprinted recon (Stage 1)")
    if scores["evasion_capability"] >= 4:
        tools.append("hiv_waf_fp.py  → WAF fingerprint + bypass chain (Stage 2-3)")
    if scores["mutation_depth"] >= 4:
        tools.append("hiv_mutator.py → polymorphic payload campaign (Stage 3)")
    if scores["evasion_capability"] >= 6:
        tools.append("rat_h3.py      → HTTP/3 QUIC delivery (CF/Akamai bypass)")
    if scores["persistence_options"] >= 5:
        tools.append("hiv_beacon.py  → dormant C2 with latency protocol (Stage 4)")
        tools.append("rat_oob.py     → OOB callback to verify persistence (Stage 4)")
    if scores["cd4_degradability"] >= 5:
        tools.append("hiv_cd4_flood.py → WAF/SIEM exhaustion before real attack (Stage 3→2)")
    if scores["lateral_surface"] >= 5:
        tools.append("rat_digest.py  → digest auth pivot for lateral movement (Stage 6)")

    if not tools:
        tools.append("No tools recommended — viral fitness too low. ABORT.")

    return tools


# ─── TIME ESTIMATE ────────────────────────────────────────────────────────────

def estimate_time(fitness: float, scores: dict) -> str:
    if fitness < SELECTIVE_STAGES:
        return "N/A (ABORT recommended)"

    days = 0
    days += 2   # always: Stage 1 recon
    days += 1   # always: WAF fingerprint
    days += 1   # Stage 2: initial access attempts

    if scores["mutation_depth"] >= 4:
        days += 2   # Stage 3: mutation campaign
    else:
        days += 1

    days += 1   # Stage 4: persistence
    days += 3   # latency period (minimum dormancy)

    if scores["lateral_surface"] >= 5:
        days += 2   # Stage 5-6: lateral movement
    elif scores["lateral_surface"] >= 3:
        days += 1

    days += 2   # final objective + evidence

    return f"~{days} days at HIV-protocol pacing (including mandatory dormancy)"


# ─── STAGE ORDERING ──────────────────────────────────────────────────────────

def optimize_stage_order(scores: dict) -> list:
    """
    HIV doesn't always follow a strict linear path.
    Sometimes evasion setup (Stage 3) should precede access (Stage 2).
    Returns recommended stage order.
    """
    order = ["Stage 1: gp120 Recon"]  # always first

    # If WAF is strong, fingerprint + prepare evasion BEFORE access attempts
    if scores["evasion_capability"] < 6:
        order.append("hiv_waf_fp.py fingerprint → configure glycan shield")
        order.append("Stage 3: Reverse Transcriptase (pre-configure mutations)")

    order.append("Stage 2: gp41 Initial Access")

    # Standard continuation
    order.extend([
        "Stage 4: Integration/Persistence → GO DARK (72h+)",
        "Stage 5: Cell Hijack (infrastructure abuse)",
        "Stage 6: Budding (lateral movement)",
        "LATENT PHASE → reactivation when safe",
    ])

    return order


# ─── SCORING REPORT ──────────────────────────────────────────────────────────

@dataclass
class FitnessReport:
    scores:         dict
    weighted_total: float
    recommendation: str
    stage_go_nogo:  dict
    stage_order:    list
    tools:          list
    time_estimate:  str
    notes:          list = field(default_factory=list)


def compute_report(scores: dict) -> FitnessReport:
    # Weighted total
    total = sum(scores[k] * WEIGHTS[k] for k in WEIGHTS)
    total = round(total, 2)

    # Recommendation
    if total >= FULL_LIFECYCLE:
        rec = "FULL_LIFECYCLE — all 6 stages, HIV-paced, full evasion overlay"
    elif total >= SELECTIVE_STAGES:
        rec = "SELECTIVE_STAGES — run high-scoring stages only, skip weak ones"
    else:
        rec = "ABORT — viral fitness too low, engagement not viable"

    # Per-stage go/no-go
    stage_gngo = {}
    for stage, reqs in STAGE_REQUIREMENTS.items():
        go = all(scores.get(factor, 0) >= min_score for factor, min_score in reqs.items())
        missing = [f"{f}>={v}" for f, v in reqs.items() if scores.get(f, 0) < v]
        stage_gngo[stage] = {
            "decision": "GO" if go else "SKIP",
            "missing":  missing if missing else [],
        }

    # Notes
    notes = []
    if scores["receptor_affinity"] < 4:
        notes.append("Low receptor affinity — target surface is restricted. Focus on passive recon only.")
    if scores["evasion_capability"] < 4:
        notes.append("High WAF strength — invest in glycan_shield + rat_h3 before any access attempt.")
    if scores["persistence_options"] < 4:
        notes.append("Limited persistence options — single-shot engagement risk. Document everything immediately.")
    if scores["cd4_degradability"] < 4:
        notes.append("Robust detection — CD4 attack (flood) may backfire. Use ultra-low rate requests only.")
    if scores["lateral_surface"] < 4:
        notes.append("Isolated target — lateral movement unlikely. Focus on depth in current scope.")

    return FitnessReport(
        scores=scores,
        weighted_total=total,
        recommendation=rec,
        stage_go_nogo=stage_gngo,
        stage_order=optimize_stage_order(scores),
        tools=recommend_tools(scores),
        time_estimate=estimate_time(total, scores),
        notes=notes,
    )


# ─── DISPLAY ─────────────────────────────────────────────────────────────────

def print_report(r: FitnessReport):
    SEP = "═" * 60

    print(f"\n{SEP}")
    print("  🧬 HIV VIRAL FITNESS REPORT")
    print(SEP)

    print("\n📊 FACTOR SCORES")
    print(f"{'Factor':<25} {'Score':>6}  {'Weight':>8}  {'Contribution':>13}")
    print("-" * 58)
    for factor, weight in WEIGHTS.items():
        score = r.scores[factor]
        contrib = score * weight
        bar = "█" * int(score) + "░" * (10 - int(score))
        print(f"  {factor:<23} {score:>5.1f}  {weight:>7.0%}  {contrib:>12.2f}  {bar}")

    print(f"\n{'─'*58}")
    print(f"  {'VIRAL FITNESS SCORE':<30} {r.weighted_total:>6.2f} / 10.0")
    print(f"{'─'*58}")

    # Color-coded recommendation
    rec_prefix = {
        "FULL_LIFECYCLE":    "✅ FULL_LIFECYCLE",
        "SELECTIVE_STAGES":  "⚡ SELECTIVE_STAGES",
        "ABORT":             "❌ ABORT",
    }
    rec_key = r.recommendation.split(" — ")[0]
    print(f"\n🎯 RECOMMENDATION: {r.recommendation}")

    print(f"\n⏱  TIME ESTIMATE: {r.time_estimate}")

    print("\n\n📋 STAGE GO/NO-GO")
    print("-" * 58)
    for stage, result in r.stage_go_nogo.items():
        icon = "✅" if result["decision"] == "GO" else "⛔"
        line = f"  {icon} {stage}"
        if result["missing"]:
            line += f"  [needs: {', '.join(result['missing'])}]"
        print(line)

    print("\n\n📐 RECOMMENDED STAGE ORDER")
    print("-" * 58)
    for i, step in enumerate(r.stage_order, 1):
        print(f"  {i:2}. {step}")

    print("\n\n🛠  TOOL INVOCATIONS")
    print("-" * 58)
    for tool in r.tools:
        print(f"  • {tool}")

    if r.notes:
        print("\n\n⚠️  NOTES")
        print("-" * 58)
        for note in r.notes:
            print(f"  ⚠  {note}")

    print(f"\n{SEP}\n")


# ─── INTERACTIVE MODE ────────────────────────────────────────────────────────

QUESTIONS = {
    "receptor_affinity": {
        "title": "Receptor Affinity — Target Surface Accessibility",
        "questions": [
            "Are public API endpoints discoverable? (JS bundles, docs, etc)",
            "Is authentication mechanism known and testable?",
            "Are input parameters accessible without auth?",
            "Does target have mobile API (often less hardened)?",
        ],
        "guidance": "0=completely locked down, 5=standard webapp, 10=API-first with full docs exposed",
    },
    "evasion_capability": {
        "title": "Evasion Capability — Your Bypass vs Their WAF",
        "questions": [
            "What WAF is deployed? (Cloudflare/Akamai/Imperva/ModSec/none)",
            "Is HTTP/3 available? (rat_h3.py bypass path)",
            "Does WAF have known bypass techniques for your target vuln class?",
            "Can you rotate IPs/proxies? (residential pool)",
        ],
        "guidance": "0=enterprise WAF with no known bypasses, 5=standard CF, 10=no WAF or WAF with known full bypass",
    },
    "persistence_options": {
        "title": "Persistence Options — Available Provirus Tiers",
        "questions": [
            "Is file write possible post-access? (webshell = Tier 3)",
            "Are OAuth apps registerable in target platform?",
            "Is there a CI/CD pipeline accessible? (Tier 4)",
            "Are subdomain CNAME records claimable? (takeover persistence)",
        ],
        "guidance": "0=stateless API only no persistence possible, 5=OAuth or webshell, 10=CI/CD+supply chain",
    },
    "mutation_depth": {
        "title": "Mutation Depth — Payload Variation Potential",
        "questions": [
            "How many encoding layers does WAF process? (URL, double, unicode)",
            "Can payloads be split across multiple parameters?",
            "Does app accept multiple content-types? (JSON, XML, form)",
            "Are there context switches? (HTML→JS→CSS→URL contexts)",
        ],
        "guidance": "0=strict allowlist no bypass possible, 5=standard WAF with known bypass set, 10=weak/no filtering",
    },
    "cd4_degradability": {
        "title": "CD4 Degradability — Detection System Susceptibility",
        "questions": [
            "Is alert threshold known or estimable?",
            "Can false positives be generated at volume?",
            "Does SOC appear to have alert fatigue (public indicators)?",
            "Is rate limiting threshold low/high?",
        ],
        "guidance": "0=ML-based anomaly detection with no threshold, 5=standard SIEM+WAF, 10=legacy rules-only SIEM",
    },
    "lateral_surface": {
        "title": "Lateral Surface — Adjacent Infrastructure for Budding",
        "questions": [
            "Are there other apps/subdomains on the same SSO?",
            "Is cloud metadata accessible via SSRF?",
            "Are internal services reachable from the foothold?",
            "Do other user accounts exist and are they testable (IDOR scope)?",
        ],
        "guidance": "0=fully isolated single-app, 5=shared SSO + some internal APIs, 10=cloud infra + k8s + multiple tenants",
    },
}


def interactive_mode() -> dict:
    scores = {}
    print("\n🧬 HIV VIRAL FITNESS SCORER — Interactive Mode")
    print("Score each factor 0.0–10.0 based on your recon findings.\n")

    for factor, info in QUESTIONS.items():
        print(f"\n{'─'*58}")
        print(f"📌 {info['title']}")
        print(f"   Guidance: {info['guidance']}")
        print("\n   Consider:")
        for q in info["questions"]:
            print(f"   • {q}")

        while True:
            try:
                val = float(input(f"\n   Score for {factor} [0.0-10.0]: ").strip())
                if 0.0 <= val <= 10.0:
                    scores[factor] = val
                    break
                print("   ❌ Must be between 0.0 and 10.0")
            except (ValueError, EOFError):
                print("   ❌ Enter a number (e.g. 6.5)")

    return scores


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HIV Viral Fitness Scorer — rate an engagement target's susceptibility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--input",  "-i", metavar="FILE", help="JSON profile input")
    parser.add_argument("--output", "-o", metavar="FILE", help="Write JSON report to file")
    args = parser.parse_args()

    if args.input:
        with open(args.input) as f:
            profile = json.load(f)
        scores = profile.get("scores", profile)
        # Validate
        missing = [k for k in WEIGHTS if k not in scores]
        if missing:
            print(f"❌ Missing factors in input: {missing}")
            sys.exit(1)
    else:
        scores = interactive_mode()

    report = compute_report(scores)
    print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(asdict(report), f, indent=2)
        print(f"📄 Report written to: {args.output}")


if __name__ == "__main__":
    main()
