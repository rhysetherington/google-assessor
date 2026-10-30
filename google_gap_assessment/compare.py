"""Compare two assessments of the same environment: what was fixed, what got worse, what is still open.

``python3 -m google_gap_assessment.compare BEFORE-Findings.json AFTER-Findings.json`` writes one self-contained HTML page with the
earlier assessment on the left and the later one on the right. Checks are matched by finding id, so the two runs may cover
different areas; a check present in only one of them is reported as such, never guessed.
"""

from __future__ import annotations

import argparse
import json
import sys
from html import escape
from pathlib import Path

from .report import HTML_CSS, _donut, _ring, score_text

OK = ("Pass", "Accepted")
LABEL = {"Pass": "Pass", "Gap": "Gap", "NotAssessed": "Not assessed", "Accepted": "Accepted", None: "Not in this run"}
BADGE = {"Pass": "c-Pass", "Gap": "c-Gap", "NotAssessed": "c-Not", "Accepted": "c-Acc", None: "c-Not"}

# Section order is deliberate: what needs attention first, good news next, then the rest.
SECTIONS = [
    ("regressed", "Got worse", "Passed before; now a gap. Look at these first."),
    ("fixed", "Fixed", "Gaps that are now closed."),
    ("worsened", "Still a gap, more affected", "The gap remains and now affects more accounts or objects."),
    ("improved", "Still a gap, fewer affected", "The gap remains but affects fewer accounts or objects than before."),
    ("now_assessed", "Now assessed", "Could not be read last time; now read."),
    ("lost", "No longer assessed", "Read last time; could not be read this time."),
    ("added", "Only in the later run", "Not part of the earlier assessment."),
    ("removed", "Only in the earlier run", "Not part of the later assessment."),
    ("open", "Still open, unchanged", "Gaps that are the same as before."),
    ("same", "Unchanged", "Passes and unread checks that did not change."),
]
CLOSED_BY_DEFAULT = {"open", "same", "removed"}


def classify(old: "dict | None", new: "dict | None") -> str:
    """One of the SECTIONS keys for a check's before and after findings."""
    if old is None:
        return "added"
    if new is None:
        return "removed"
    o, n = old["Status"], new["Status"]
    if o == "Gap" and n in OK:
        return "fixed"
    if o in OK and n == "Gap":
        return "regressed"
    if o == "NotAssessed" and n != "NotAssessed":
        return "now_assessed"
    if o != "NotAssessed" and n == "NotAssessed":
        return "lost"
    if o == n == "Gap":
        if new.get("AffectedCount", 0) > old.get("AffectedCount", 0):
            return "worsened"
        if new.get("AffectedCount", 0) < old.get("AffectedCount", 0):
            return "improved"
        return "open"
    return "same"


def compare(before: dict, after: dict) -> dict:
    """Group every check id seen in either assessment by what changed."""
    b = {f["FindingId"]: f for f in before["Findings"]}
    a = {f["FindingId"]: f for f in after["Findings"]}
    groups: "dict[str, list[tuple[dict | None, dict | None]]]" = {k: [] for k, _, _ in SECTIONS}
    sev = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for fid in sorted(set(b) | set(a), key=lambda i: (sev.get((a.get(i) or b.get(i))["Severity"], 9), i)):
        groups[classify(b.get(fid), a.get(fid))].append((b.get(fid), a.get(fid)))
    delta = None
    if before.get("Score") is not None and after.get("Score") is not None:
        delta = round(after["Score"] - before["Score"], 1)
    return {"groups": groups, "delta": delta}


def _when(a: dict) -> str:
    return (a.get("Metadata") or {}).get("AssessmentDate") or str(a.get("AssessedAt", ""))[:10] or "earlier"


def _badge(status: "str | None") -> str:
    return f'<span class="badge {BADGE[status]}">{escape(LABEL[status])}</span>'


def _note(old: "dict | None", new: "dict | None") -> str:
    ob, nb = (old or {}), (new or {})
    if ob.get("Status") == "Gap" and nb.get("Status") == "Gap":
        return f"{ob.get('AffectedCount', 0)} &rarr; {nb.get('AffectedCount', 0)} affected"
    if nb.get("Status") == "Gap" and nb.get("AffectedCount"):
        return f"{nb['AffectedCount']} affected"
    if nb.get("Status") == "NotAssessed":
        return escape((nb.get("Detail") or "")[:140])
    return ""


COMPARE_CSS = """
.cmpring{display:grid;grid-template-columns:1fr auto 1fr;gap:20px;align-items:center}
.side{display:flex;flex-direction:column;align-items:center;gap:6px;text-align:center}.side .ring{width:150px;height:150px}.side .ring b{font-size:34px}
.side .ring .track{stroke:var(--soft)}.side .ring .arc{stroke:var(--accent)}.side .ring span{color:var(--mute)}.side h3{margin:0}.side .meta{margin:0}
.delta{font-size:30px;font-weight:700;padding:8px 18px;border-radius:99px;color:#fff;background:var(--na);white-space:nowrap}.delta.up{background:var(--pass)}.delta.down{background:var(--critical)}
@media(max-width:700px){.cmpring{grid-template-columns:1fr}.delta{justify-self:center}}
.rows{width:100%}.rows th{font-size:12px;text-transform:uppercase;letter-spacing:.06em}.rows td.arrow{color:var(--mute);width:24px;text-align:center}
.rows td.chk{width:46%}.rows td.chk b{display:block}.rows tr.sev td.chk{border-left:4px solid var(--c);padding-left:12px}
.rows .id{color:var(--mute);font-size:12px}
"""


def to_html(before: dict, after: dict) -> str:
    e = escape
    res = compare(before, after)
    g, delta = res["groups"], res["delta"]
    m = after.get("Metadata") or {}
    title = f"{m.get('AssessmentName') or 'Security Gap Assessment'}: before and after"
    client = m.get("ClientName") or "Client"
    pill = ("delta" if delta is None else "delta up" if delta > 0 else "delta down" if delta < 0 else "delta")
    pill_text = "n/a" if delta is None else f"{delta:+g} pts"
    fixed, reg = len(g["fixed"]), len(g["regressed"])
    out = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} - {e(client)}</title><style>{HTML_CSS}{COMPARE_CSS}</style></head><body>
<header class="hero"><div class="wrap"><div><div class="eyebrow">Progress report</div><h1>{e(title)}</h1>
<div class="chips"><span class="chip">Prepared for <b>{e(client)}</b></span><span class="chip">{e(_when(before))} &rarr; {e(_when(after))}</span></div></div></div></header>
<main class="wrap"><section><div class="card"><div class="cmpring">
<div class="side"><h3>Before</h3><p class="meta">{e(_when(before))}</p>{_ring(before.get('Score'))}
<span class="meta">{before['Summary']['Passed']} passed &middot; {before['Summary']['Gaps']} gaps &middot; {before['Summary']['NotAssessed']} unread</span></div>
<div class="{pill}" title="Change in compliance score">{pill_text}</div>
<div class="side"><h3>After</h3><p class="meta">{e(_when(after))}</p>{_ring(after.get('Score'))}
<span class="meta">{after['Summary']['Passed']} passed &middot; {after['Summary']['Gaps']} gaps &middot; {after['Summary']['NotAssessed']} unread</span></div></div>
<div class="stats" style="margin:22px 0 0">
<div class="stat pass"><b>{fixed}</b><span>gaps fixed</span></div>
<div class="stat gap"><b>{reg}</b><span>got worse</span></div>
<div class="stat"><b>{len(g['open']) + len(g['worsened']) + len(g['improved'])}</b><span>gaps still open</span></div>
<div class="stat na"><b>{len(g['now_assessed'])}</b><span>newly assessed</span></div></div>
<p class="meta" style="margin:16px 0 0">Checks are matched by id. A score that includes more checks read than before can move for that reason as well as for real fixes; see &ldquo;Now assessed&rdquo; and &ldquo;No longer assessed&rdquo;.</p></div></section>"""]
    for key, heading, blurb in SECTIONS:
        rows = g[key]
        if not rows:
            continue
        out.append(f'<section><details{"" if key in CLOSED_BY_DEFAULT else " open"}><summary>{e(heading)} <span class="count">{len(rows)}</span></summary><div class="body">'
                   f'<p class="meta">{e(blurb)}</p><table class="rows"><tr><th>Check</th><th>Before</th><th></th><th>After</th><th>Detail</th></tr>')
        for old, new in rows:
            ref = new or old
            out.append(f'<tr class="sev c-{e(ref["Severity"])}"><td class="chk"><b>{e(ref["Name"])}</b><span class="id">{e(ref["FindingId"])} &middot; {e(ref["Severity"])}</span></td>'
                       f'<td>{_badge(old["Status"] if old else None)}</td><td class="arrow">&rarr;</td><td>{_badge(new["Status"] if new else None)}</td><td>{_note(old, new)}</td></tr>')
        out.append("</table></div></details></section>")
    out.append(f"<footer>Compared by google_gap_assessment. Read-only: both assessments only read settings; nothing was changed. "
               f"Earlier run: {e(str(before.get('AssessedAt', ''))[:16].replace('T', ' '))} UTC. Later run: {e(str(after.get('AssessedAt', ''))[:16].replace('T', ' '))} UTC.</footer></main></body></html>")
    return "".join(out)


def write_comparison(before: dict, after: dict, out_path: Path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(to_html(before, after), encoding="utf-8")
    try:
        out_path.chmod(0o600)  # contains the tenant's account names
    except OSError:
        pass
    return out_path


def _load(path: str) -> dict:
    p = Path(path).expanduser()
    if not p.is_file():
        raise ValueError(f"File not found: {path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("Findings"), list) or "Summary" not in data:
        raise ValueError(f"{path} is not an assessment Findings file (expected the *-Findings.json a run writes).")
    return data


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(prog="google_gap_assessment.compare", description="Compare two assessments: earlier on the left, later on the right.")
    ap.add_argument("before", help="the earlier assessment's *-Findings.json")
    ap.add_argument("after", help="the later assessment's *-Findings.json")
    ap.add_argument("--out", metavar="FILE", help="where to write the HTML (default: next to the later file, *-Comparison.html)")
    args = ap.parse_args(argv)
    try:
        before, after = _load(args.before), _load(args.after)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    out = Path(args.out) if args.out else Path(args.after).expanduser().with_name(Path(args.after).name.replace("-Findings.json", "") + "-Comparison.html")
    write_comparison(before, after, out)
    g = compare(before, after)["groups"]
    print(f"Score {score_text(before)} -> {score_text(after)} | fixed {len(g['fixed'])}, got worse {len(g['regressed'])}, "
          f"still open {len(g['open']) + len(g['worsened']) + len(g['improved'])}, newly assessed {len(g['now_assessed'])}")
    print(f"  wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
