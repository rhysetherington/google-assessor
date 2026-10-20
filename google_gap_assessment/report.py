"""Render an assessment as Markdown or HTML, and write the report files."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from html import escape
from itertools import groupby
from pathlib import Path

from . import evidence
from .metadata import base_name

HTML_CSS = """
:root{--bg:#f4f6f9;--card:#fff;--ink:#17202c;--mute:#5a6879;--line:#e1e6ed;--soft:#eef2f7;--critical:#b42318;--high:#d9480f;--medium:#b7791f;--low:#2f6fba;--pass:#1b7f4b;--hero1:#0f2742;--hero2:#1d4ed8}
@media (prefers-color-scheme:dark){:root{--bg:#0e141b;--card:#161e28;--ink:#e6ebf2;--mute:#9aa8b9;--line:#263241;--soft:#1d2733;--critical:#f97066;--high:#ff8a4c;--medium:#e3b341;--low:#6ea8ff;--pass:#4cc38a;--hero1:#0b1a2e;--hero2:#1e3a8a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.hero{background:linear-gradient(135deg,var(--hero1),var(--hero2));color:#fff;padding:40px 20px 56px}.wrap{max-width:1040px;margin:0 auto;padding:0 20px}.hero .wrap{padding:0}
.eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:12px;opacity:.8}h1{margin:6px 0 8px;font-size:32px;line-height:1.15}h2{margin:32px 0 12px;font-size:22px}.hero p{margin:0;opacity:.85}
main{margin-top:-32px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px 22px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}.stat{background:var(--soft);border-radius:10px;padding:12px 14px}.stat b{font-size:26px;display:block;line-height:1.2}.stat span{color:var(--mute);font-size:13px}
.badge{display:inline-block;padding:1px 10px;border-radius:99px;color:#fff;font-size:11.5px;font-weight:700;text-transform:uppercase}
.bg-Critical{background:var(--critical)}.bg-High{background:var(--high)}.bg-Medium{background:var(--medium)}.bg-Low{background:var(--low)}
details{background:var(--card);border:1px solid var(--line);border-radius:12px;margin:10px 0}details>summary{cursor:pointer;padding:12px 16px;font-weight:600;display:flex;gap:10px;align-items:center}
details .body{padding:2px 18px 16px;border-top:1px solid var(--line);overflow-x:auto}details.sub{background:var(--soft);border:0;border-radius:8px}
.meta{color:var(--mute);font-size:13px}code{background:var(--soft);padding:1px 6px;border-radius:5px;font-size:12.5px}ul,ol{margin:6px 0 6px 20px;padding:0}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{padding:7px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mute)}
.s-Gap{color:var(--critical);font-weight:600}.s-Pass{color:var(--pass);font-weight:600}.s-Not{color:var(--mute);font-weight:600}
footer{color:var(--mute);font-size:12.5px;margin-top:36px;padding-top:16px;border-top:1px solid var(--line)}
@media print{body{background:#fff}.card,details{break-inside:avoid}}
"""


def md_cell(text: object) -> str:
    """Resource names and principals come from the project; they must not become live Markdown/HTML in a viewer."""
    return re.sub(r"\r?\n", " ", str(text).replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|"))


def score_text(a: dict) -> str:
    return "Not calculated" if a.get("Score") is None else f"{a['Score']}%"


def scope_text(a: dict) -> str:
    sc, parts = a["Scope"], []
    if sc.get("Workspace"):
        parts.append(f"Google Workspace tenant {sc['Workspace']['PrimaryDomain']}")
    if sc.get("Projects"):
        n = len(sc["Projects"])
        text = f"{n} Google Cloud project{'s' if n != 1 else ''}"
        if sc.get("OrganizationId"):
            text += f", organisation {sc['OrganizationId']}"
        if sc.get("FolderId"):
            text += f", folder {sc['FolderId']}"
        parts.append(text)
    text = "; ".join(parts) or "nothing"
    if a.get("OnlyChecks"):  # a re-run of specific checks must not be mistaken for a full assessment
        text += f". PARTIAL ASSESSMENT: only {', '.join(a['OnlyChecks'])} were run"
    return text


def compliance_matrix(findings: "list[dict]") -> "list[dict]":
    """One row per NIST CSF 2.0 subcategory: worst status wins (Gap > Not assessed > Accepted > Pass)."""
    rows = []
    for nist, grp in groupby(sorted(findings, key=lambda f: f["NistCsf"]), key=lambda f: f["NistCsf"]):
        grp = list(grp)
        statuses = {f["Status"] for f in grp}
        status = ("Gap" if "Gap" in statuses else "Not assessed" if "NotAssessed" in statuses
                  else "Accepted" if "Accepted" in statuses else "Pass")
        rows.append({"Nist": nist, "Scf": ", ".join(sorted({f["ScfControl"] for f in grp})), "Status": status,
                     "Finding": ", ".join(f["FindingId"] for f in grp)})
    return rows


def _gaps_by_domain(findings: "list[dict]"):
    gaps = sorted((f for f in findings if f["Status"] == "Gap"), key=lambda f: f["Domain"])
    return [(d, list(g_)) for d, g_ in groupby(gaps, key=lambda f: f["Domain"])]


def to_markdown(a: dict, evidence_root: "Path | None" = None) -> str:
    f = a["Findings"]
    sev, m, s = a["Summary"]["GapsBySeverity"], a["Metadata"], a["Summary"]
    md = [f"# {md_cell(m.get('AssessmentName') or 'Google Cloud Security Gap Assessment')}", "", "| | |\n|---|---|"]
    if m.get("ClientName"): md.append(f"| **Client** | {md_cell(m['ClientName'])} |")
    if m.get("AssessmentDate"): md.append(f"| **Assessment date** | {md_cell(m['AssessmentDate'])} |")
    if m.get("AssessorName"):
        md.append(f"| **Assessor** | {md_cell(m['AssessorName'])}{', ' + md_cell(m['PreparedBy']) if m.get('PreparedBy') else ''} |")
    if m.get("Reference"): md.append(f"| **Reference** | {md_cell(m['Reference'])} |")
    md += [f"| **Scope** | {md_cell(scope_text(a))} |",
           f"| **Assessed** | {a['AssessedAt'][:16].replace('T', ' ')} UTC by {md_cell(a['AssessedBy'])} |",
           f"| **Tool version** | google_gap_assessment {a['ModuleVersion']} (read-only) |", "",
           "## Executive Summary", "", "| Metric | Value |\n|---|---|",
           f"| Compliance score | **{score_text(a)}** |", f"| Checks performed | {s['TotalChecks']} |", f"| Passed | {s['Passed']} |",
           f"| Gaps | {s['Gaps']} |", f"| Not assessed (permission or error) | {s['NotAssessed']} |"]
    if s["Accepted"]: md.append(f"| Accepted risks | {s['Accepted']} |")
    md += ["", f"| Critical | High | Medium | Low |\n|:-:|:-:|:-:|:-:|\n| {sev['Critical']} | {sev['High']} | {sev['Medium']} | {sev['Low']} |", "",
           ]
    ws = a["Scope"].get("Workspace")
    if ws:
        md += ["## Google Workspace Tenant", "", "| | |\n|---|---|", f"| **Primary domain** | {md_cell(ws['PrimaryDomain'])} |",
               f"| **Domains checked** | {md_cell(', '.join(ws['Domains']))} |", ""]
    if a["Scope"].get("Projects"):
        md += ["## Projects Assessed", "", "| Project | Name | Number |\n|---|---|---|"]
        md += [f"| {md_cell(p['ProjectId'])} | {md_cell(p['Name'])} | {md_cell(p['ProjectNumber'])} |" for p in a["Scope"]["Projects"]]
    md += ["", "## Control Compliance Matrix (NIST CSF 2.0 / SCF)", "", "| NIST CSF 2.0 | SCF | Status | Findings |\n|---|---|---|---|"]
    md += [f"| {r['Nist']} | {r['Scf']} | {r['Status']} | {r['Finding']} |" for r in compliance_matrix(f)]
    md += ["", "## Detailed Findings by Domain"]
    for domain, items in _gaps_by_domain(f):
        md += ["", f"### {domain}"]
        for g_ in items:
            cis = f"  |  **CIS GCP Foundations:** {', '.join(g_['CisControl'])}" if g_["CisControl"] else ""
            md += ["", f"#### [{g_['Severity']}] {g_['FindingId']} - {g_['Name']}", "", f"- **SCF:** {g_['ScfControl']}  |  **NIST CSF 2.0:** {g_['NistCsf']}{cis}"]
            if g_["Detail"]: md.append(f"- **Detail:** {md_cell(g_['Detail'])}")
            if g_["AffectedCount"] > 0:
                md.append(f"- **Affected ({g_['AffectedCount']}):**")
                md += [f"  - {md_cell(x)}" for x in g_["AffectedObjects"][:25]]
                ev = evidence.evidence_link(g_, evidence_root)
                if g_["AffectedCount"] > 25:
                    md.append(f"  - ...and {g_['AffectedCount'] - 25} more ({'see ' + ev if ev else 'see the Findings JSON file'})")
                if ev: md.append(f"- **Evidence:** [{ev}]({ev}) (all {g_['AffectedCount']} items)")
            md += ["", "**Remediation:**", ""] + [f"{i}. {step}" for i, step in enumerate(g_["Remediation"], 1)]
    na = [x for x in f if x["Status"] == "NotAssessed"]
    if na: md += ["", "## Checks Not Assessed", ""] + [f"- **{n['FindingId']}** {n['Name']}: {md_cell(n['Detail'])}" for n in na]
    acc = [x for x in f if x["Status"] == "Accepted"]
    if acc:
        md += ["", "## Accepted Risks", ""]
        for x in acc:
            r = x["AcceptedRisk"]
            md.append(f"- **{x['FindingId']}** {x['Name']}: {md_cell(r['Reason'])} (approved by {r.get('ApprovedBy') or 'n/a'}"
                      f"{', expires ' + str(r['Expires']) if r.get('Expires') else ''})")
    ok = [x for x in f if x["Status"] == "Pass"]
    if ok: md += ["", "## Checks Passed", ""] + [f"- {x['FindingId']} {x['Name']}" for x in ok]
    return "\n".join(md)


def to_html(a: dict, brand_color: "str | None" = None, evidence_root: "Path | None" = None) -> str:
    e = escape
    f, sev, s, m = a["Findings"], a["Summary"]["GapsBySeverity"], a["Summary"], a["Metadata"]
    title = m.get("AssessmentName") or "Google Cloud Security Gap Assessment"
    client = m.get("ClientName") or "Client"
    accent = f":root{{--hero2:{brand_color}}}" if brand_color and re.fullmatch(r"#[0-9a-fA-F]{6}", brand_color) else ""
    out = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} - {e(client)}</title><style>{HTML_CSS}{accent}</style></head><body>
<header class="hero"><div class="wrap"><div class="eyebrow">Security assessment</div><h1>{e(title)}</h1>
<p>Prepared for <b>{e(client)}</b>{' by ' + e(m['PreparedBy']) if m.get('PreparedBy') else ''} &middot; {e(m.get('AssessmentDate', ''))}{' &middot; Assessor ' + e(m['AssessorName']) if m.get('AssessorName') else ''}{' &middot; Ref ' + e(m['Reference']) if m.get('Reference') else ''}</p></div></header>
<main class="wrap"><section><div class="card"><div class="stats">
<div class="stat"><b>{e(score_text(a))}</b><span>compliance score</span></div>
<div class="stat"><b>{s['Passed']}</b><span>checks passed</span></div>
<div class="stat"><b>{s['Gaps']}</b><span>gaps found</span></div>
<div class="stat"><b>{sev['Critical']} / {sev['High']} / {sev['Medium']} / {sev['Low']}</b><span>critical / high / medium / low</span></div>
{f'<div class="stat"><b>{s["Accepted"]}</b><span>accepted risks</span></div>' if s['Accepted'] else ''}
{f'<div class="stat"><b>{s["NotAssessed"]}</b><span>not assessable</span></div>' if s['NotAssessed'] else ''}
</div><p class="meta">Scope: {e(scope_text(a))}. A pass means the setting that was read looks right; it is not proof the project is secure.</p></div></section>
<section><h2>Findings</h2>"""]
    domains = _gaps_by_domain(f)
    if not domains: out.append("<p>No gaps were found in the checks that could be assessed.</p>")
    for domain, items in domains:
        out.append(f'<details><summary>{e(domain)} <span class="meta">{len(items)} gap{"s" if len(items) != 1 else ""}</span></summary><div class="body">')
        for g_ in items:
            out.append(f'<details class="sub"><summary><span class="badge bg-{g_["Severity"]}">{g_["Severity"]}</span>{e(g_["Name"])}</summary><div class="body" style="border:0">')
            cis = f' &middot; CIS GCP <code>{e(", ".join(g_["CisControl"]))}</code>' if g_["CisControl"] else ""
            out.append(f'<div class="meta"><code>{e(g_["FindingId"])}</code> &middot; SCF <code>{e(g_["ScfControl"])}</code> &middot; NIST CSF 2.0 <code>{e(g_["NistCsf"])}</code>{cis}</div>')
            if g_["Detail"]: out.append(f"<p>{e(g_['Detail'])}</p>")
            if g_["AffectedCount"] > 0:
                ev = evidence.evidence_link(g_, evidence_root)
                out.append(f"<b>Affected ({g_['AffectedCount']})</b><ul>" + "".join(f"<li>{e(x)}</li>" for x in g_["AffectedObjects"][:25]))
                if g_["AffectedCount"] > 25:
                    out.append(f"<li>&hellip;and {g_['AffectedCount'] - 25} more ({'see ' + e(ev) if ev else 'see the Findings JSON file'})</li>")
                out.append("</ul>")
                if ev: out.append(f'<p class="meta">Evidence file: <a href="{e(ev)}">{e(ev)}</a> (all {g_["AffectedCount"]} items)</p>')
            out.append("<b>Remediation</b><ol>" + "".join(f"<li>{e(step)}</li>" for step in g_["Remediation"]) + "</ol></div></details>")
        out.append("</div></details>")
    out.append("</section>")
    na = [x for x in f if x["Status"] == "NotAssessed"]
    if na:
        out.append("<section><h2>Checks not assessed</h2><ul>" + "".join(f"<li><code>{e(n['FindingId'])}</code> {e(n['Name'])}: {e(n['Detail'])}</li>" for n in na) + "</ul></section>")
    out.append('<section><h2>Appendix</h2>')
    ws = a["Scope"].get("Workspace")
    if ws:
        out.append(f'<details><summary>Google Workspace tenant</summary><div class="body"><table><tr><th>Primary domain</th><td>{e(ws["PrimaryDomain"])}</td></tr>'
                   f'<tr><th>Domains checked</th><td>{e(", ".join(ws["Domains"]))}</td></tr></table></div></details>')
    if a["Scope"].get("Projects"):
        out.append('<details><summary>Projects assessed</summary><div class="body"><table><tr><th>Project</th><th>Name</th><th>Number</th></tr>')
        out += [f"<tr><td>{e(p['ProjectId'])}</td><td>{e(p['Name'])}</td><td>{e(p['ProjectNumber'])}</td></tr>" for p in a["Scope"]["Projects"]]
        out.append('</table></div></details>')
    out.append('<details><summary>Control compliance matrix (NIST CSF 2.0 / SCF)</summary><div class="body"><table><tr><th>NIST CSF 2.0</th><th>SCF</th><th>Status</th><th>Findings</th></tr>')
    for r in compliance_matrix(f):
        cls = {"Gap": "s-Gap", "Pass": "s-Pass", "Accepted": "s-Pass"}.get(r["Status"], "s-Not")
        out.append(f'<tr><td>{e(r["Nist"])}</td><td>{e(r["Scf"])}</td><td class="{cls}">{e(r["Status"])}</td><td>{e(r["Finding"])}</td></tr>')
    out.append("</table></div></details></section>")
    out.append(f"<footer>Assessed {e(a['AssessedAt'][:16].replace('T', ' '))} UTC &middot; google_gap_assessment {e(a['ModuleVersion'])}. Read-only assessment: no changes were made to any project.</footer></main></body></html>")
    return "".join(out)


def protect(path: Path) -> None:
    """Restrict the report folder to the current user (700 folder / 600 files); reports hold project IDs, principals and gaps."""
    if sys.platform.startswith("win"):
        return
    os.chmod(path, stat.S_IRWXU)
    for child in path.rglob("*"):
        os.chmod(child, stat.S_IRWXU if child.is_dir() else stat.S_IRUSR | stat.S_IWUSR)


def export(assessment: dict, export_path: Path, formats=("JSON", "Markdown"), brand_color: "str | None" = None,
           include_evidence: bool = False) -> "list[str]":
    """Write the Findings JSON (always) plus Markdown and/or HTML. Returns the files written."""
    export_path = Path(export_path)
    export_path.mkdir(parents=True, exist_ok=True)
    written: "list[str]" = []
    # Evidence first, so each finding carries its EvidenceFile path into the JSON and the reports.
    if include_evidence:
        written += [str(p) for p in evidence.write_files(assessment, export_path)]
    base = base_name(assessment)
    json_path = export_path / (f"{base}-Findings.json" if base else "AssessmentFindings.json")
    json_path.write_text(json.dumps({k: v for k, v in assessment.items() if k != "ExportedFiles"}, indent=2), encoding="utf-8")
    written.append(str(json_path))
    if "Markdown" in formats:
        p = export_path / (f"{base}-Assessment.md" if base else "GCP_Security_Gap_Assessment.md")
        p.write_text(to_markdown(assessment, export_path), encoding="utf-8")
        written.append(str(p))
    if "HTML" in formats:
        p = export_path / (f"{base}-Assessment.html" if base else "GCP_Security_Gap_Assessment.html")
        p.write_text(to_html(assessment, brand_color, export_path), encoding="utf-8")
        written.append(str(p))
    protect(export_path)
    return written
