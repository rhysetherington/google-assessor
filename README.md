# Google Assessor

A **read-only** security gap assessment for **Google Workspace** and **Google Cloud**, in one tool. It reads your configuration, compares it
with **155 checks**, and produces a scored report (HTML, Markdown and JSON) with remediation steps.

- **Google Workspace** (108 checks): identity and 2-step verification, Gmail and email security (including SPF, DKIM, DMARC), Drive and
  Docs sharing, Groups, Meet, Calendar, Chat, Classroom and Sites. Built around the
  [CISA SCuBA](https://github.com/cisagov/ScubaGoggles) secure configuration baselines, with checks of our own on top.
- **Google Cloud** (47 checks): IAM, logging, networking, Compute Engine, Cloud Storage, Cloud SQL, Cloud KMS and organization policy,
  mapped to the CIS Google Cloud Platform Foundation Benchmark.

When you run it, it asks what you want to assess: **Google Workspace only**, **Google Workspace and Google Cloud**, or **Google Cloud only**.
Every check is mapped to SCF and NIST CSF 2.0. It is the Google sibling of the M365 Assessor and produces the same kind of report.

- **Read-only, enforced in code.** Workspace is read over HTTPS with a GET-only client, read-only OAuth scopes and a host allowlist.
  Google Cloud is read through one gcloud gateway that runs only `list`, `describe` and `get-iam-policy`. Tests scan the source so a
  write cannot be added unnoticed.
- **Honest about what it cannot see.** A setting it cannot read (missing role or edition, an API error, a field Google did not return) is
  *NotAssessed* and counts against the score, never a pass. A product that is switched off is *not applicable*.
- **Nothing is stored.** No credentials, tenant or project IDs live in the code or on disk. Sign-in is done by gcloud, and you are asked for
  what to assess each run.
- **No dependencies.** Python standard library only; the test suite replaces Google with fixtures.

> **Not affiliated with CISA.** This is an independent tool. The SCuBA baselines are CISA's work (released under CC0); this project cites
> their policy IDs to show what each check covers, and records which of them it does not cover and why (see
> [`Docs/Coverage.md`](Docs/Coverage.md)).

## Quick start

You need Python 3.11 or later and the [Google Cloud CLI](https://cloud.google.com/sdk/docs/install).

```bash
git clone https://github.com/rhysetherington/google-assessor.git
cd google-assessor
python3 -m google_gap_assessment            # asks: Workspace only / Workspace and Cloud / Cloud only
```

### Google Workspace

Reading a Workspace tenant needs a **Super Admin** to sign in once with read-only scopes. Google does not let gcloud's own login request
the Admin SDK scopes, so you bring your own OAuth client (a Desktop app in a project you control). The tool prints the steps:

```bash
python3 -m google_gap_assessment --setup-help --quota-project my-project     # the five-minute, one-time setup
python3 -m google_gap_assessment --scope workspace --quota-project my-project
```

The setup enables the Admin SDK and Cloud Identity APIs in that project, then runs
`gcloud auth application-default login --client-id-file=... --scopes=<the read-only scopes>`. Sign out afterwards with
`gcloud auth application-default revoke`. No key file is created and no secret is stored by this tool.

### Google Cloud

```bash
gcloud auth login
python3 -m google_gap_assessment --scope cloud --project-id my-project-id --format JSON Markdown HTML
```

Give it `--folder-id` or `--organization-id` instead to assess the projects directly under them. Use a read-only account (Viewer and Security
Reviewer) or `--impersonate-service-account`; an account that can change resources is flagged and you are asked to confirm.

### Both

```bash
python3 -m google_gap_assessment --scope both --quota-project my-project --project-id my-project-id --corporate-domain contoso.com
```

You are asked for report details (client name, assessor, date) unless you pass `--no-prompt`. Reports go to
`./GoogleAssessment/<ClientName>-<date>/`; open the `.html` file. `python3 -m google_gap_assessment --help` lists every option.

## What is checked

[`Docs/Coverage.md`](Docs/Coverage.md) lists every check with its severity and framework mappings. In short:

| Target | Domain | Checks | Covers |
|---|---|---|---|
| Workspace | `Identity` | GID-001 to 031 | 2SV enforcement and method, device trust, sessions, passwords, super admins and their sign-in, stale accounts, recovery, app and API access, Marketplace, Takeout, alerts, data regions, multi-party approval, DLP |
| Workspace | `Gmail` | GML-001 to 034 | delegation, forwarding, POP/IMAP, attachment and link protection, spoofing protection, spam bypasses, mail storage, and DNS: DKIM, SPF, DMARC, MTA-STS, TLS-RPT for every domain |
| Workspace | `Drive` | GDR-001 to 014 | external sharing mode and what depends on it, link defaults, shared drives, link-security update, Drive SDK and desktop |
| Workspace | `Groups`, `Meet`, `Calendar`, `Chat`, `Classroom`, `Sites` | GGR, GMT, GCL, GCH, GCR, GST | external access and membership, who can join meetings, calendar sharing, chat history and external chat, class membership |
| Cloud | `Iam`, `Logging`, `Network`, `Compute`, `Storage`, `Sql`, `OrgPolicy`, `Kms` | IAM, LOG, NET, CMP, STO, SQL, ORG, KMS | see the coverage page (`Kms` is opt-in) |

Not every SCuBA policy can be checked automatically. **105 of the 138 are covered**; the other 33 are listed with the reason (no API exposes it,
only the admin audit log shows it, field names could not be verified, or it is a deliberate choice).

## Permissions and data

**Workspace:** a Super Admin signs in with these read-only scopes (`admin.directory.*.readonly`, `admin.reports.audit.readonly`,
`cloud-identity.policies.readonly`, `cloud-identity.inboundsso.readonly`); the tool checks the token holds them and says which are missing. It
asks the Directory API only for the fields it needs (no names, phone numbers or addresses) and never reads mail, files or calendar contents.
**The tenant's domain names are sent to a DNS-over-HTTPS resolver** (Cloudflare by default; `--doh-endpoint` changes it, `--no-dns` skips
those checks).

**Google Cloud:** Viewer (`roles/viewer`) and Security Reviewer (`roles/iam.securityReviewer`); Organization Policy Viewer for the org-policy
checks, API Keys Viewer for the API-key checks, Cloud KMS Viewer for the `Kms` domain, Browser on a folder or organisation for
`--folder-id` / `--organization-id`. A missing role makes the affected checks *NotAssessed*; it never fails the run.

Reports contain real information about your tenant and projects (domains, user e-mail addresses, project IDs, resource names). The report
folders are git-ignored, restricted to your user on macOS and Linux, and instance metadata (SSH keys, startup scripts) and API key strings are
never written.

## Redo one check, or a few

```bash
python3 -m google_gap_assessment --list-checks
python3 -m google_gap_assessment --check GML-028 GID-005 IAM-003      # scope and connections are worked out for you
```

Only the domains that own those checks run, and only the data they need is read. The report is labelled **PARTIAL ASSESSMENT** so it cannot be
mistaken for a full one.

## Accepted risks

```json
{ "risks": [ { "findingId": "GML-033", "reason": "Partner allowlist reviewed quarterly", "approvedBy": "J. Smith", "expires": "2027-06-30",
               "affected": ["contoso.com: / - spam-filter override 'Partner allowlist'"] } ] }
```

Pass the file with `--accepted-risk-path`. `affected` is optional (omit it to accept the whole finding); every affected object must be covered
or the finding stays a Gap. An expired acceptance stops applying. Files named `*accepted*.json` are git-ignored.

## How it is organised

```
google_gap_assessment/
  workspace/          client.py (GET-only HTTPS), auth.py (gcloud ADC token), policy.py (Policy API reducer), directory.py, mail_dns.py, session.py
    checks/           identity.py gmail.py drive.py groups.py meet.py calendar.py chat.py classroom.py sites.py
  cloud/              gcloud.py (read-only gateway), scope.py, guard.py
    checks/           iam.py audit_logging.py network.py compute.py storage.py sql.py kms.py orgpolicy.py
  data/               control_mapping.json (every check), scuba_policies.json (CISA policy index and what is not covered)
  assess.py  report.py  model.py  registry.py  ...        run, score, report, merge
tests_python/         workspace/ and checks/ hold one test file per domain
```

Each check is a short function (or one row of a table) with a docstring saying what it tests. Most Workspace checks are one `PolicyRule`
row: a finding id, the admin-console setting, a predicate and a reason. The reducer handles Google's per-OU and per-group overrides, so a
check is judged at the top-level OU **and** wherever an OU or group overrides it.

## Status and limits

**The Google Cloud checks have been run against one live (empty) project. The Google Workspace checks have not yet been run against a live
tenant**; they are verified only against a fake tenant built from the documented API shapes. Setting field names come from CISA's reference
implementation and its published test data and could differ from what your tenant returns. A field that does not match shows up as
*NotAssessed* rather than a wrong answer, but expect first-run tuning. Google's Policy API only returns settings your edition includes, and the
admin-console settings it exposes are a subset of everything in the console.

Treat the output as a review aid, not an audit: the checks follow published guidance, some only approximate a recommendation, and a pass means
the setting that was read looks right, not that the tenant is secure. CIS numbers follow v3.0.0 and should be confirmed against the edition you
hold.

## Tests and extending

```bash
python3 -m unittest discover -s tests_python -t .        # offline, about a second
python3 -m unittest tests_python.workspace.test_gmail    # one domain
python3 -m google_gap_assessment.coverage                # regenerate Docs/Coverage.md after changing the mapping
```

To add a check: (1) add it to `google_gap_assessment/data/control_mapping.json` (id, domain, name, severity, SCF, NIST CSF, CIS or SCuBA
references, remediation; ids are never reused); (2) in the domain module, add a `PolicyRule` row or a function decorated with
`@check("XXX-000")`; (3) return *NotAssessed*, never *Pass*, for anything that could not be read; (4) add a case to the domain's test file. The
registry tests fail if a mapped id has no function, a function has no docstring, an id is registered twice, or a SCuBA reference is not a
real policy.

## Licence

[MIT](LICENSE).
