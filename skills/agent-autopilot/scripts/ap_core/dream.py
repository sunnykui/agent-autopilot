"""Daily Dream consolidation: pitfall routing (advisory vs human-gated proposals) and 48h concurrency maturation."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

from .db import AutopilotDB
from .models import POLICY_MANIFEST, default_state_root, ensure_secure_dir, now_iso, now_utc, sanitize_terminal_text


def sync_project_pitfalls_markdown(
    db: AutopilotDB,
    project_id: str,
    *,
    state_root: Path | None = None,
    advisory_dir: Path | None = None,
) -> Path:
    """Immediately refresh `PITFALLS.md` from SQLite so the very next issue run inherits newly learned pitfalls!"""
    max_chars = int(POLICY_MANIFEST["chef_pipeline"]["max_pitfall_rule_chars"])
    rows = db._conn.execute(
        "SELECT * FROM pitfalls WHERE project_id = ? ORDER BY hits DESC, updated_at DESC LIMIT 50",
        (project_id,),
    ).fetchall()
    adv_dir = ensure_secure_dir(advisory_dir if advisory_dir is not None else ((state_root or default_state_root()) / "advisory" / project_id), 0o700)
    pit_md = adv_dir / "PITFALLS.md"
    lines = [
        f"# {project_id} Pitfall Rules (Advisory — Excluded from Referee & Visual)",
        "",
    ]
    for r in rows:
        sym = sanitize_terminal_text(r["symptom"], max_chars)
        rul = sanitize_terminal_text(r["rule_text"], max_chars)
        lines.append(f"- [{r['target_area']}] {sym} -> {rul} (hits={r['hits']})")
    pit_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return pit_md


def run_dream_consolidation(
    db: AutopilotDB,
    *,
    state_root: Path | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Route pitfalls to advisory PITFALLS.md or human-gated proposals/, and mature >=48h clean runs."""
    sroot = state_root or default_state_root()
    ref_now = now or now_utc()
    maturity_hours = int(POLICY_MANIFEST["chef_pipeline"]["staircase_maturity_hours"])
    max_chars = int(POLICY_MANIFEST["chef_pipeline"]["max_pitfall_rule_chars"])

    # 1. Mature clean runs older than 48h without subsequent veto/rollback on the same unit
    cutoff_iso = (ref_now - dt.timedelta(hours=maturity_hours)).replace(microsecond=0).isoformat()
    matured_count = 0
    with db.immediate_tx():
        rows = db._conn.execute(
            """
            SELECT h.run_id, h.project_id, h.unit_key
            FROM run_history h
            JOIN work_units u ON u.unit_key = h.unit_key
            WHERE h.status = 'published'
              AND h.matured_clean = 0
              AND h.completed_at <= ?
              AND u.veto_pending = 0
              AND COALESCE(u.terminal_state, '') != 'needs-human'
            """,
            (cutoff_iso,),
        ).fetchall()
        for r in rows:
            db._conn.execute("UPDATE run_history SET matured_clean = 1 WHERE run_id = ?", (r["run_id"],))
            db._conn.execute(
                "UPDATE projects SET clean_matured_runs = clean_matured_runs + 1, updated_at = ? WHERE project_id = ?",
                (now_iso(), r["project_id"]),
            )
            matured_count += 1

    # 2. Route pitfalls per Principle 03
    pit_rows = db._conn.execute("SELECT * FROM pitfalls ORDER BY hits DESC, updated_at DESC").fetchall()
    by_project: dict[str, list[dict[str, Any]]] = {}
    by_rule_projects: dict[str, set[str]] = {}
    gate_proposals: list[str] = []
    lesson_proposals: list[str] = []

    for prow in pit_rows:
        p = dict(prow)
        by_project.setdefault(p["project_id"], []).append(p)
        by_rule_projects.setdefault(p["rule_text"], set()).add(p["project_id"])

    for pid, items in by_project.items():
        adv_dir = ensure_secure_dir(sroot / "advisory" / pid, 0o700)
        pit_md = adv_dir / "PITFALLS.md"
        lines = [
            f"# {pid} Pitfall Rules (Advisory — Excluded from Referee & Visual)",
            "",
        ]
        for it in items[:50]:
            sym = sanitize_terminal_text(it["symptom"], max_chars)
            rul = sanitize_terminal_text(it["rule_text"], max_chars)
            lines.append(f"- [{it['target_area']}] {sym} -> {rul} (hits={it['hits']})")

            # Hits >= 2 -> propose executable gate promotion (human-gated, SHA-256 bound)
            if int(it["hits"]) >= 2:
                prop_dir = ensure_secure_dir(sroot / "proposals" / it["sig"], 0o700)
                gate_payload = {
                    "sig": it["sig"],
                    "project_id": pid,
                    "target_area": it["target_area"],
                    "hits": int(it["hits"]),
                    "proposed_rule": rul,
                    "requires_human_approval": True,
                }
                raw_json = json.dumps(gate_payload, ensure_ascii=False, indent=2) + "\n"
                gate_payload["sha256"] = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
                gp = prop_dir / "gate_patch.json"
                gp.write_text(json.dumps(gate_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                gate_proposals.append(str(gp))

            # Seen across >= 2 projects -> propose cross-project LESSONS_LEARNED.patch (human-gated)
            if len(by_rule_projects.get(it["rule_text"], set())) >= 2:
                prop_dir = ensure_secure_dir(sroot / "proposals" / it["sig"], 0o700)
                lp = prop_dir / "LESSONS_LEARNED.patch"
                patch_txt = f"+ - **坑点**：{sym} → **规矩**：{rul}\n"
                lp.write_text(patch_txt, encoding="utf-8")
                lesson_proposals.append(str(lp))

        pit_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 3. Check staircase promotion eligibility
    min_clean = int(POLICY_MANIFEST["chef_pipeline"]["staircase_min_clean_runs"])
    steps = POLICY_MANIFEST["chef_pipeline"]["staircase_concurrency_steps"]
    eligible_promotions: list[dict[str, Any]] = []
    for pr in db._conn.execute("SELECT * FROM projects").fetchall():
        idx = int(pr["current_step_idx"])
        if int(pr["clean_matured_runs"]) >= min_clean and idx + 1 < len(steps):
            eligible_promotions.append(
                {
                    "project_id": pr["project_id"],
                    "current_max_in_progress": pr["max_in_progress"],
                    "proposed_max_in_progress": steps[idx + 1],
                    "clean_matured_runs": pr["clean_matured_runs"],
                }
            )

    return {
        "matured_runs": matured_count,
        "projects_updated": sorted(by_project.keys()),
        "gate_proposals": gate_proposals,
        "lesson_proposals": lesson_proposals,
        "eligible_promotions": eligible_promotions,
    }
