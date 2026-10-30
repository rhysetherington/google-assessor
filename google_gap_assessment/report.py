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
from .model import SEVERITY_ORDER

HTML_CSS = """
:root{--bg:#f3f5f9;--card:#fff;--ink:#16202e;--mute:#5b6b7e;--line:#e3e8ef;--soft:#eef2f8;--critical:#c0261b;--high:#e0561a;--medium:#c58a12;--low:#2f78c4;--pass:#1b8a52;--na:#8a97a8;--hero1:#0d2340;--hero2:#2457d6;--accent:var(--hero2);--shadow:0 1px 2px rgba(16,32,56,.06),0 6px 20px rgba(16,32,56,.06)}
@media (prefers-color-scheme:dark){:root{--bg:#0d131a;--card:#151d27;--ink:#e7ecf3;--mute:#9aabbd;--line:#243142;--soft:#1c2733;--critical:#ff7b70;--high:#ff9455;--medium:#e8b84a;--low:#73aaff;--pass:#4fcb8c;--na:#6f7f92;--hero1:#0a1829;--hero2:#2b4fb8;--shadow:0 1px 2px rgba(0,0,0,.4),0 6px 20px rgba(0,0,0,.3)}}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}code{background:var(--soft);padding:1px 6px;border-radius:5px;font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px}
.hero{background:radial-gradient(1200px 400px at 85% -10%,rgba(255,255,255,.14),transparent 60%),linear-gradient(135deg,var(--hero1),var(--hero2));color:#fff;padding:44px 0 92px}
.hero .wrap{display:flex;gap:32px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:12px;opacity:.75;font-weight:600}
h1{margin:8px 0 14px;font-size:34px;line-height:1.15;letter-spacing:-.01em}h2{margin:0 0 14px;font-size:20px;letter-spacing:-.005em}h3{margin:0;font-size:15px}
.chips{display:flex;flex-wrap:wrap;gap:8px}.chip{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.2);border-radius:99px;padding:3px 12px;font-size:13px}
.ring{width:176px;height:176px;position:relative;flex:none}.ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.ring .track{stroke:rgba(255,255,255,.2)}.ring .arc{stroke:#fff;stroke-linecap:round}
.ring .num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}.ring b{font-size:40px;line-height:1}.ring span{font-size:12px;opacity:.8;margin-top:4px;text-transform:uppercase;letter-spacing:.08em}
main{margin-top:-60px;padding-bottom:40px}section{margin-bottom:28px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px 24px;box-shadow:var(--shadow)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.stat{background:var(--soft);border-radius:12px;padding:14px 16px;border-left:4px solid var(--na)}.stat b{font-size:28px;display:block;line-height:1.1}.stat span{color:var(--mute);font-size:13px}
.stat.pass{border-color:var(--pass)}.stat.gap{border-color:var(--critical)}.stat.na{border-color:var(--na)}.stat.acc{border-color:var(--low)}
.bar{display:flex;height:14px;border-radius:99px;overflow:hidden;background:var(--soft)}.bar i{display:block;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin:10px 0 0;font-size:13px;color:var(--mute)}.legend span:before{content:"";display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;background:var(--c);vertical-align:-1px}
.c-Critical{--c:var(--critical)}.c-High{--c:var(--high)}.c-Medium{--c:var(--medium)}.c-Low{--c:var(--low)}.c-Pass{--c:var(--pass)}.c-Gap{--c:var(--critical)}.c-Not{--c:var(--na)}.c-Acc{--c:var(--low)}
.bar i{background:var(--c)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px}@media(max-width:760px){.grid2{grid-template-columns:1fr}.hero h1{font-size:27px}}
.lead{color:var(--mute);margin:0 0 16px}
.start{display:grid;gap:10px}.start a{display:flex;gap:12px;align-items:flex-start;text-decoration:none;color:inherit;background:var(--soft);border-radius:12px;padding:12px 14px;border-left:4px solid var(--c)}
.start a:hover{filter:brightness(.97)}.start b{display:block}.start small{color:var(--mute);display:block;line-height:1.4}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;color:#fff;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;background:var(--c);white-space:nowrap}
.dom{display:grid;grid-template-columns:minmax(150px,230px) 1fr 80px;gap:12px;align-items:center;padding:7px 0;font-size:14px}.dom .n{text-align:right;color:var(--mute);font-variant-numeric:tabular-nums}
@media(max-width:620px){.dom{grid-template-columns:1fr 70px}.dom .bar{grid-column:1/-1;order:3}}
.tools{display:none;flex-wrap:wrap;gap:8px;margin:0 0 14px;align-items:center}.js .tools{display:flex}
.tools button{font:inherit;font-size:13px;border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:99px;padding:4px 14px;cursor:pointer}
.tools button[aria-pressed=true]{background:var(--ink);color:var(--card);border-color:var(--ink)}.tools .sp{flex:1}
details{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:10px 0;box-shadow:var(--shadow)}
details>summary{cursor:pointer;padding:13px 18px;font-weight:600;display:flex;gap:10px;align-items:center;list-style:none}details>summary::-webkit-details-marker{display:none}
details>summary:after{content:"\\25B8";margin-left:auto;color:var(--mute);transition:transform .15s}details[open]>summary:after{transform:rotate(90deg)}
.count{font-weight:500;color:var(--mute);font-size:13px}
.body{padding:4px 20px 18px;border-top:1px solid var(--line);overflow-x:auto}
.finding{box-shadow:none;border-left:5px solid var(--c);background:var(--card)}.finding>summary{font-weight:600}
.finding .why{margin:12px 0 4px}.finding h4{margin:16px 0 6px;font-size:12.5px;text-transform:uppercase;letter-spacing:.07em;color:var(--mute)}
.map{display:flex;flex-wrap:wrap;gap:6px;margin-top:16px}.map code{background:var(--soft)}
ul,ol{margin:6px 0 6px 20px;padding:0}li{margin:3px 0}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mute);font-weight:600}
.s-Gap{color:var(--critical);font-weight:600}.s-Pass{color:var(--pass);font-weight:600}.s-Not{color:var(--mute);font-weight:600}
.reason{background:var(--soft);border-radius:12px;padding:12px 16px;margin:10px 0}.reason p{margin:0 0 6px;color:var(--mute);font-size:14px}
.cols{columns:2 300px;column-gap:28px;list-style:none;margin:6px 0;padding:0}.cols li{break-inside:avoid;font-size:14px;padding-left:20px;position:relative}.cols li:before{content:"\\2713";position:absolute;left:0;color:var(--pass);font-weight:700}
.meta{color:var(--mute);font-size:13px}
footer{color:var(--mute);font-size:12.5px;margin-top:36px;padding-top:16px;border-top:1px solid var(--line)}
@media print{body{background:#fff}.hero{padding:24px 0 36px;-webkit-print-color-adjust:exact;print-color-adjust:exact}main{margin-top:-24px}.tools{display:none!important}.card,details{break-inside:avoid;box-shadow:none}.bar i,.badge,.stat{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""

HTML_JS = """
(function(){var d=document,r=d.documentElement;r.classList.add('js');
var fs=d.querySelectorAll('.finding'),bs=d.querySelectorAll('.tools [data-f]');
function apply(f){bs.forEach(function(b){b.setAttribute('aria-pressed',String(b.dataset.f===f))});
fs.forEach(function(x){x.hidden=!(f==='all'||x.dataset.sev===f)});
d.querySelectorAll('.domain').forEach(function(s){s.hidden=!s.querySelector('.finding:not([hidden])')})}
bs.forEach(function(b){b.addEventListener('click',function(){apply(b.dataset.f)})});
d.querySelectorAll('[data-open]').forEach(function(b){b.addEventListener('click',function(){var o=b.dataset.open==='1';d.querySelectorAll('#findings details').forEach(function(x){x.open=o})})});
addEventListener('beforeprint',function(){d.querySelectorAll('details').forEach(function(x){x.open=true})});
})();
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


def _ring(score) -> str:
    """Score ring: an SVG circle whose arc length is the score. Pure markup, no script."""
    circ = 2 * 3.14159265 * 52
    pct = 0 if score is None else max(0.0, min(100.0, float(score)))
    label = "not calculated" if score is None else f"{pct:g}%"
    return (f'<div class="ring" role="img" aria-label="Compliance score {escape(label)}"><svg viewBox="0 0 120 120">'
            f'<circle class="track" cx="60" cy="60" r="52" fill="none" stroke-width="10"/>'
            f'<circle class="arc" cx="60" cy="60" r="52" fill="none" stroke-width="10" stroke-dasharray="{circ:.1f}" stroke-dashoffset="{circ * (1 - pct / 100):.1f}"/></svg>'
            f'<div class="num"><b>{escape("n/a" if score is None else f"{pct:g}%")}</b><span>score</span></div></div>')


def _bar(parts: "list[tuple[str, int, str]]") -> str:
    """Stacked bar from (css class, count, title). Zero-width parts are skipped."""
    total = sum(n for _, n, _ in parts) or 1
    return '<div class="bar">' + "".join(
        f'<i class="{c}" style="width:{n / total * 100:.2f}%" title="{escape(t)}"></i>' for c, n, t in parts if n) + "</div>"


def _not_assessed_groups(items: "list[dict]") -> "list[tuple[str, list[dict]]]":
    """Group not-assessed checks by the reason in the last pair of brackets, so one cause is stated once."""
    groups: "dict[str, list[dict]]" = {}
    for x in items:
        detail = (x["Detail"] or "No reason recorded").strip()
        rest = re.sub(r"^Could not be assessed in \d+ project\(s\):\s*", "", detail)   # drop the "in N tenant(s)" lead-in
        single = re.fullmatch(r"[^()]*\((.*)\)", rest, re.S)                            # "tenant.example (the reason)" -> the reason
        groups.setdefault((single.group(1) if single else rest).strip(), []).append(x)
    return sorted(groups.items(), key=lambda kv: -len(kv[1]))


def to_html(a: dict, brand_color: "str | None" = None, evidence_root: "Path | None" = None) -> str:
    e = escape
    f, sev, s, m = a["Findings"], a["Summary"]["GapsBySeverity"], a["Summary"], a["Metadata"]
    title = m.get("AssessmentName") or "Google Cloud Security Gap Assessment"
    client = m.get("ClientName") or "Client"
    accent = f":root{{--hero2:{brand_color}}}" if brand_color and re.fullmatch(r"#[0-9a-fA-F]{6}", brand_color) else ""
    chips = [f"Prepared for <b>{e(client)}</b>"]
    if m.get("AssessmentDate"): chips.append(e(m["AssessmentDate"]))
    if m.get("AssessorName"): chips.append("Assessor " + e(m["AssessorName"]) + (", " + e(m["PreparedBy"]) if m.get("PreparedBy") else ""))
    if m.get("Reference"): chips.append("Ref " + e(m["Reference"]))
    out = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} - {e(client)}</title><style>{HTML_CSS}{accent}</style></head><body>
<header class="hero"><div class="wrap"><div><div class="eyebrow">Security assessment</div><h1>{e(title)}</h1>
<div class="chips">{''.join(f'<span class="chip">{c}</span>' for c in chips)}</div>
<p class="meta" style="color:rgba(255,255,255,.75);margin:14px 0 0;max-width:640px">{e(scope_text(a))}</p></div>{_ring(a.get('Score'))}</div></header>
<main class="wrap"><section><div class="card"><div class="stats">
<div class="stat pass"><b>{s['Passed']}</b><span>checks passed</span></div>
<div class="stat gap"><b>{s['Gaps']}</b><span>gaps found</span></div>
<div class="stat na"><b>{s['NotAssessed']}</b><span>could not be assessed</span></div>
{f'<div class="stat acc"><b>{s["Accepted"]}</b><span>accepted risks</span></div>' if s['Accepted'] else ''}
<div class="stat"><b>{s['TotalChecks']}</b><span>checks run</span></div></div>
<div class="grid2"><div><h3>Gaps by severity</h3>{_bar([("c-Critical", sev['Critical'], "Critical"), ("c-High", sev['High'], "High"), ("c-Medium", sev['Medium'], "Medium"), ("c-Low", sev['Low'], "Low")])}
<div class="legend">{''.join(f'<span class="c-{k}">{k} {sev[k]}</span>' for k in ('Critical', 'High', 'Medium', 'Low'))}</div></div>
<div><h3>All checks</h3>{_bar([("c-Pass", s['Passed'], "Passed"), ("c-Gap", s['Gaps'], "Gaps"), ("c-Not", s['NotAssessed'], "Not assessed"), ("c-Acc", s['Accepted'], "Accepted")])}
<div class="legend"><span class="c-Pass">Passed {s['Passed']}</span><span class="c-Gap">Gaps {s['Gaps']}</span><span class="c-Not">Not assessed {s['NotAssessed']}</span></div></div></div>
<p class="meta" style="margin:16px 0 0">A pass means the setting that was read looks right; it is not proof the environment is secure. Checks that could not be read count against the score and are never shown as passes.</p></div></section>"""]

    urgent = sorted((x for x in f if x["Status"] == "Gap" and x["Severity"] in ("Critical", "High")), key=lambda x: (SEVERITY_ORDER[x["Severity"]], x["FindingId"]))
    if urgent:
        out.append('<section><div class="card"><h2>Start here</h2><p class="lead">The most serious gaps. Fixing these first removes the most risk.</p><div class="start">')
        for x in urgent:
            out.append(f'<a href="#f-{e(x["FindingId"])}" class="c-{x["Severity"]}"><span class="badge c-{x["Severity"]}">{x["Severity"]}</span>'
                       f'<span><b>{e(x["Name"])}</b><small>{e(x["Detail"])}</small></span></a>')
        out.append("</div></div></section>")

    by_domain: "dict[str, dict[str, int]]" = {}
    for x in f:
        by_domain.setdefault(x["Domain"], {"Pass": 0, "Gap": 0, "NotAssessed": 0, "Accepted": 0})[x["Status"]] += 1
    if len(by_domain) > 1:
        out.append('<section><div class="card"><h2>By area</h2>')
        for d, c in by_domain.items():
            tot = sum(c.values())
            out.append(f'<div class="dom"><span>{e(d)}</span>{_bar([("c-Pass", c["Pass"], "Passed"), ("c-Gap", c["Gap"], "Gaps"), ("c-Not", c["NotAssessed"], "Not assessed"), ("c-Acc", c["Accepted"], "Accepted")])}'
                       f'<span class="n">{c["Pass"]}/{tot} pass</span></div>')
        out.append("</div></section>")

    out.append('<section id="findings"><h2>Findings</h2>')
    # Most serious area first: by its worst severity, then by how many gaps it has, then by name.
    domains = sorted(_gaps_by_domain(f), key=lambda dg: (min(SEVERITY_ORDER[g_["Severity"]] for g_ in dg[1]), -len(dg[1]), dg[0]))
    if not domains:
        out.append('<div class="card">No gaps were found in the checks that could be assessed.</div>')
    else:
        present = [k for k in ("Critical", "High", "Medium", "Low") if sev[k]]
        out.append('<div class="tools"><button type="button" data-f="all" aria-pressed="true">All ' + str(s["Gaps"]) + "</button>"
                   + "".join(f'<button type="button" data-f="{k}" aria-pressed="false">{k} {sev[k]}</button>' for k in present)
                   + '<span class="sp"></span><button type="button" data-open="1">Expand all</button><button type="button" data-open="0">Collapse all</button></div>')
    for domain, items in domains:
        worst = min(SEVERITY_ORDER[g_["Severity"]] for g_ in items)
        out.append(f'<details class="domain"{" open" if worst <= SEVERITY_ORDER["High"] else ""}><summary>{e(domain)} <span class="count">{len(items)} gap{"s" if len(items) != 1 else ""}</span></summary><div class="body">')
        for g_ in sorted(items, key=lambda x: (SEVERITY_ORDER[x["Severity"]], x["FindingId"])):
            out.append(f'<details class="finding c-{g_["Severity"]}" id="f-{e(g_["FindingId"])}" data-sev="{g_["Severity"]}"><summary><span class="badge c-{g_["Severity"]}">{g_["Severity"]}</span>{e(g_["Name"])}</summary><div class="body" style="border:0">')
            if g_["Detail"]: out.append(f'<p class="why">{e(g_["Detail"])}</p>')
            if g_["AffectedCount"] > 0:
                ev = evidence.evidence_link(g_, evidence_root)
                out.append(f"<h4>Affected ({g_['AffectedCount']})</h4><ul>" + "".join(f"<li>{e(x)}</li>" for x in g_["AffectedObjects"][:25]))
                if g_["AffectedCount"] > 25:
                    out.append(f"<li>&hellip;and {g_['AffectedCount'] - 25} more ({'see ' + e(ev) if ev else 'see the Findings JSON file'})</li>")
                out.append("</ul>")
                if ev: out.append(f'<p class="meta">Evidence file: <a href="{e(ev)}">{e(ev)}</a> (all {g_["AffectedCount"]} items)</p>')
            out.append("<h4>How to fix it</h4><ol>" + "".join(f"<li>{e(step)}</li>" for step in g_["Remediation"]) + "</ol>")
            cis = f'<code>CIS GCP {e(", ".join(g_["CisControl"]))}</code>' if g_["CisControl"] else ""
            out.append(f'<div class="map"><code>{e(g_["FindingId"])}</code><code>SCF {e(g_["ScfControl"])}</code><code>NIST CSF 2.0 {e(g_["NistCsf"])}</code>{cis}</div></div></details>')
        out.append("</div></details>")
    out.append("</section>")

    na = [x for x in f if x["Status"] == "NotAssessed"]
    if na:
        out.append(f'<section><div class="card"><h2>Could not be assessed ({len(na)})</h2><p class="lead">These checks count against the score until they can be read. Each reason is listed once with the checks it affects.</p>')
        for reason, items in _not_assessed_groups(na):
            out.append(f'<div class="reason"><p>{e(reason)}</p><ul>' + "".join(f"<li><code>{e(x['FindingId'])}</code> {e(x['Name'])}</li>" for x in items) + "</ul></div>")
        out.append("</div></section>")

    acc = [x for x in f if x["Status"] == "Accepted"]
    if acc:
        out.append('<section><div class="card"><h2>Accepted risks</h2><ul>' + "".join(
            f"<li><code>{e(x['FindingId'])}</code> {e(x['Name'])}: {e(x['AcceptedRisk']['Reason'])}</li>" for x in acc) + "</ul></div></section>")

    ok = [x for x in f if x["Status"] == "Pass"]
    out.append('<section><h2>Appendix</h2>')
    if ok:
        out.append(f'<details><summary>Checks passed <span class="count">{len(ok)}</span></summary><div class="body"><ul class="cols">'
                   + "".join(f"<li>{e(x['Name'])}</li>" for x in ok) + "</ul></div></details>")
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
    out.append(f"<footer>Assessed {e(a['AssessedAt'][:16].replace('T', ' '))} UTC &middot; google_gap_assessment {e(a['ModuleVersion'])}. "
               f"Read-only assessment: no changes were made to any setting, user or resource.</footer></main><script>{HTML_JS}</script></body></html>")
    return "".join(out)


def protect(path: Path) -> None:
    """Restrict the report folder to the current user (700 folder / 600 files); reports hold project IDs, principals and gaps."""
    if sys.platform.startswith("win"):
        return
    os.chmod(path, stat.S_IRWXU)
    for child in path.rglob("*"):
        os.chmod(child, stat.S_IRWXU if child.is_dir() else stat.S_IRUSR | stat.S_IWUSR)


def export(assessment: dict, export_path: Path, formats=("JSON", "Markdown", "HTML"), brand_color: "str | None" = None,
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
