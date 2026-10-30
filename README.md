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
- **Nothing is stored.** No credentials, tenant or project IDs live in the code or on disk. The Workspace sign-in is done by the tool itself with
  read-only permissions, kept in memory and revoked when the run ends; you are asked for what to assess each run.
- **No dependencies.** Python standard library only; the test suite replaces Google with fixtures.

> **Not affiliated with CISA.** This is an independent tool. The SCuBA baselines are CISA's work (released under CC0); this project cites
> their policy IDs to show what each check covers, and records which of them it does not cover and why (see
> [`Docs/Coverage.md`](Docs/Coverage.md)).

## Objective and scope

**Objective.** Give an IT administrator or consultant a repeatable, **read-only** way to measure how securely a Google environment is
configured against published guidance, to show a client what to fix first, and later to show how far they have come. It is the Google sibling
of the M365 Assessor and produces the same kind of scored report.

**In scope**

- **Google Workspace tenants**: identity and 2-step verification, Gmail and email authentication (including live SPF, DKIM, DMARC, MTA-STS and
  TLS-RPT lookups), Drive and Docs sharing, Groups, Meet, Calendar, Chat, Classroom and Sites.
- **Google Cloud**: projects, folders and organisations (IAM, logging, networking, Compute Engine, Cloud Storage, Cloud SQL, Cloud KMS and
  organisation policy).
- **Two commands**: *assess* (run an assessment) and *compare* (pick a saved assessment and compare it with a later one, earlier on the left).
- **Reports** in HTML (for the client), Markdown and JSON, optional evidence CSVs, accepted-risk handling, and framework mappings to SCF,
  NIST CSF 2.0, CIS Google Cloud Foundations and CISA SCuBA.

**Out of scope, by design**

- **Making changes.** The tool never fixes anything; it tells you what to change and how.
- **Reading content.** It does not read mail, files or calendar contents, and asks the Directory API only for the fields it needs.
- **Settings Google does not expose by API**, settings only visible in the admin audit log, and Gemini settings (field names could not be
  verified). Each uncovered SCuBA policy is listed in [`Docs/Coverage.md`](Docs/Coverage.md) with the reason.
- **Other clouds, and continuous monitoring.** A run is a point-in-time snapshot; compare runs to see change.

## Quick start

> **Running this for a client or as an administrator?** Follow the step-by-step guide: [`Docs/Instructions.md`](Docs/Instructions.md).

You need Python 3.11 or later and the [Google Cloud CLI](https://cloud.google.com/sdk/docs/install).

```bash
git clone https://github.com/rhysetherington/google-assessor.git
cd google-assessor
python3 -m google_gap_assessment            # asks: Workspace only / Workspace and Cloud / Cloud only
```

**Two commands:** `python3 -m google_gap_assessment` runs an assessment; `python3 -m google_gap_assessment compare` lets you choose a saved
assessment and compare it with a later one, earlier on the left and later on the right (see [`Docs/Instructions.md`](Docs/Instructions.md)).

### Google Workspace

Reading a Workspace tenant needs a **Super Admin** to sign in. The tool does the sign-in itself (it opens your browser), using an OAuth client
from a Google Cloud project you control. One-time setup, about five minutes; `--setup-help` prints it:

1. In the Cloud Console create a project and enable the **Admin SDK API** and **Cloud Identity API**.
2. Under *OAuth consent screen* choose **Internal**; under *Credentials* create an OAuth client of type **Desktop app** and download its JSON to
   somewhere outside any git folder, for example `~/.config/client_secret.json`.
3. Run the assessment and sign in as the Super Admin when the browser opens:

```bash
python3 -m google_gap_assessment --scope workspace --oauth-client-file ~/.config/client_secret.json
```

The tool asks for the read-only permissions only (viewing users, groups, domains, admin roles and settings), keeps the sign-in in memory, never
writes a token to disk, and **revokes the sign-in when the run ends**. It does not use `gcloud auth application-default login` for this because
gcloud refuses to issue that credential without the broad `cloud-platform` scope, which could change Google Cloud data; the tool warns if it is ever
given such a token.

### Google Cloud

```bash
gcloud auth login
python3 -m google_gap_assessment --scope cloud --project-id my-project-id
```

Give it `--folder-id` or `--organization-id` instead to assess the projects directly under them. Use a read-only account (Viewer and Security
Reviewer) or `--impersonate-service-account`; an account that can change resources is flagged and you are asked to confirm.

### Both

```bash
python3 -m google_gap_assessment --scope both --oauth-client-file ~/.config/client_secret.json --project-id my-project-id --corporate-domain contoso.com
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
`cloud-identity.policies.readonly`, `cloud-identity.inboundsso.readonly`); the tool checks the token holds them and says which are missing. Google has no
Global Reader equivalent for these settings, so the account has to be a Super Admin even though the tool only reads: use a dedicated admin account
with 2-step verification. (Whether a narrower custom admin role can read every setting is untested.) It
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
  workspace/          client.py (GET-only HTTPS), auth.py (browser sign-in, tokens), policy.py (Policy API reducer), directory.py, mail_dns.py, session.py
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

**What has been run live.** The Google Cloud checks have been run once against a free, empty project. The Google Workspace checks have been run
several times against one newly created Workspace tenant (signed in as a Super Admin), including with the email DNS lookups on a domain the
tester owns. In those runs 104 of the 108 Workspace checks returned a result; the other four settings (POP/IMAP, default link sharing,
conflicting unmanaged accounts, multi-party approval) return no value on a tenant that has never changed them, so they stay *NotAssessed*
rather than guess a default Google does not document.

**What that does and does not show.** A live run proves the sign-in, the API calls, the policy reducer and the reports work against real
Google responses, and that a real configuration change shows up in a comparison. It is **one blank tenant on one edition**, so it does not prove
every check's pass and gap logic against every configuration. Setting and field names come from CISA's reference implementation, which is used on
live tenants; in addition, 10 of the 79 admin-console rule checks have been confirmed against real Policy API responses (CISA's published test
data, no mismatches), and the reducer that turns Google's per-OU and per-group policies into one value is checked against that data's expected
results. For the rest, a field that does not match your tenant shows up as *NotAssessed* rather than a wrong answer. Google's Policy API only
returns settings your edition includes, and the admin-console settings it exposes are a subset of everything in the console.

Treat the output as a review aid, not an audit: the checks follow published guidance, some only approximate a recommendation, and a pass means
the setting that was read looks right, not that the tenant is secure. CIS numbers follow v3.0.0 and should be confirmed against the edition you
hold.

## How it was built

The work, in the order it happened:

1. **Google Cloud assessor.** Started as a read-only PowerShell assessor over the `gcloud` CLI, then **ported to Python 3.11 using only the standard
   library**, so there is nothing to install and it runs on macOS, Linux and Windows. (The PowerShell version is not part of this repository.)
2. **Structured by domain.** Each area is its own module and each check is one function or one table row, so an auditor can redo a single check
   (`--check ID`) without re-running everything. The report is stamped *PARTIAL ASSESSMENT* when that happens.
3. **Read-only enforced in code, not by convention.** One gcloud gateway that only allows `list`, `describe` and `get-iam-policy`; a GET-only HTTPS
   client with a host allowlist and read-only OAuth scopes for Workspace; tests that scan the source so a write cannot be added unnoticed.
4. **Workspace support.** Built around the 138 CISA SCuBA policies (105 covered, the rest documented with a reason), reading the Cloud Identity
   Policy API (with a reducer for per-OU and per-group overrides), the Directory API for users, groups, domains and admin roles, and DNS-over-HTTPS
   for email authentication.
5. **Its own sign-in.** The plan was to reuse `gcloud auth application-default login`. Testing showed gcloud refuses that credential without the
   broad `cloud-platform` scope, which could change Cloud data. So the tool does its own browser sign-in (OAuth with PKCE, read-only scopes only,
   held in memory, revoked when the run ends) and warns if it is ever given a write-capable token.
6. **Honest scoring.** A setting that cannot be read is *NotAssessed* and counts against the score. It is never a pass.
7. **Reports.** Markdown and JSON, then a client-ready HTML report (score ring, charts, a heat-map by area, an executive summary, filterable findings
   and an optional logo), evidence CSVs and accepted-risk handling.
8. **Compare.** A second command that lists saved assessments, lets the assessor pick the one to start from, and shows what was fixed, what got worse
   and what is still open, earlier on the left and later on the right.
9. **Documentation.** An administrator manual ([`Docs/Instructions.md`](Docs/Instructions.md)) and a generated coverage page
   ([`Docs/Coverage.md`](Docs/Coverage.md)).

## Testing

| Layer | What it covers |
|---|---|
| **Offline tests** | Over 230 tests that run in about two seconds with Google replaced by fixtures: a fake tenant for every Workspace domain and a fake gcloud for Cloud. Each check has pass, gap and not-assessed cases |
| **Real-data oracle** | The Policy API reducer is run against CISA's real published responses (CC0). This found a genuine bug (a missing reducer for list-type settings), since fixed |
| **Read-only guarantees** | Tests scan the source: the only POSTs are OAuth housekeeping, the gcloud gateway rejects anything but read verbs, and hostile names in reports are escaped |
| **Documentation guards** | Tests fail if the README's headline numbers or `Docs/Coverage.md` drift from the data |
| **Continuous integration** | GitHub Actions runs the suite on Linux, macOS and Windows with Python 3.11 and 3.13 (this caught a Windows path bug) |
| **Live: Google Cloud** | One read-only run against a free, empty project |
| **Live: Google Workspace** | Several runs against a newly created tenant as a Super Admin, with and without the DNS lookups, and a before/after comparison after real configuration changes |

**What live testing found, and what changed because of it**

- gcloud's sign-in could not be used safely (see above), so the tool signs the admin in itself.
- **False passes.** The first live run scored 84.3%, but 96 of those passes were really "the API is not enabled in the sign-in project". That is correct
  for a Cloud project and wrong for Workspace. It now reports *NotAssessed* with the fix, and a test covers it.
- **False email gaps.** Google's receive-only test alias domain (`<domain>.test-google-a.com`) was being checked for SPF, DKIM and DMARC. It cannot send
  mail, so it is now skipped.
- **Unset settings.** Where a setting has never been changed Google returns nothing. The tool applies a default only where Google documents it
  (for example, per-user outbound gateways are off); otherwise the check stays *NotAssessed*.
- A real change (sharing and app-access settings) was detected by the comparison as fixed gaps, and the new email results were separated from real
  fixes under "Now assessed", so the score change is not overstated.

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
