# Google Cloud Assessor

A **read-only** Google Cloud security gap assessment you can run against your own projects with the
[Google Cloud CLI](https://cloud.google.com/sdk/docs/install) (`gcloud`). It reads your configuration, compares it with
**47 checks** across IAM, logging, networking, Compute Engine, Cloud Storage, Cloud SQL, Cloud KMS and organization policy, and produces a
scored report (HTML, Markdown and JSON) with remediation steps. Every check is mapped to SCF and NIST CSF 2.0 and, where it matches, to the
CIS Google Cloud Platform Foundation Benchmark. It is the Google Cloud sibling of the M365 Assessor and produces the same kind of report.

- **Read-only.** Every call goes through one gateway that runs only `gcloud` commands ending in `list`, `describe` or `get-iam-policy` and
  refuses anything else; a test scans the source so a write command cannot be added unnoticed.
- **Least privilege.** Built for a **Viewer + Security Reviewer** account, or a dedicated read-only service account that you impersonate
  (`--impersonate-service-account`). If the account you sign in with holds Owner or Editor the tool asks you to confirm, and refuses to run
  unattended that way unless you pass `--allow-elevated-account`.
- **Honest about what it cannot see.** A setting it cannot read (missing permission, error, a field gcloud did not return) is reported as
  *NotAssessed* and counted against the score, never as a pass. A service that is not enabled in a project is reported as not applicable.
- **Secrets stay out.** Instance metadata (SSH keys, startup scripts) and API key strings are never written to a report; only booleans and
  resource names are kept.
- **No dependencies.** Python standard library only. The offline test suite replaces gcloud with fixtures.

## Try it on your project

You need Python 3.11 or later and the Google Cloud CLI, signed in:

```bash
gcloud auth login
git clone https://github.com/rhysetherington/google-assessor.git
cd google-assessor
python3 -m google_gap_assessment --project-id my-project-id --format JSON Markdown HTML
```

If you leave out `--project-id` (and `--folder-id` / `--organization-id`) you are asked for the project. You are also asked for a client name,
assessor and date for the report header (`--no-prompt` accepts the defaults). Reports are written to `./GcpAssessment/<ClientName>-<date>/`;
open the `.html` file. Run `python3 -m google_gap_assessment --help` for every option.

```bash
# Everything directly under an organisation, as a dedicated read-only service account, against your own e-mail domains
python3 -m google_gap_assessment --organization-id 123456789012 --corporate-domain contoso.com \
    --impersonate-service-account assessor@security-project.iam.gserviceaccount.com --include-evidence --format JSON Markdown HTML

# Only some domains; Kms is opt-in and scans the locations you name
python3 -m google_gap_assessment --project-id my-project-id --domain Iam Network Kms --kms-location global --kms-location europe-west2
```

From Python: `from google_gap_assessment.assess import run_assessment, export_assessment` (see `__main__.py` for a worked example).

## Domains

| Domain | Checks | Notes |
|---|---|---|
| `Iam` | IAM-001 to IAM-011 | Project IAM policy, service accounts and their keys, API keys. |
| `Logging` | LOG-001 to LOG-003 | Audit logs, a sink for all logs, locked retention on the export bucket. |
| `Network` | NET-001 to NET-008 | Default / legacy networks, SSH, RDP and any-any from the internet, flow logs, DNSSEC. |
| `Compute` | CMP-001 to CMP-008 | Default service account, scopes, SSH keys, OS Login, serial port, IP forwarding, Shielded VM, external IPs. GKE nodes are skipped. |
| `Storage` | STO-001, STO-002 | Public buckets, uniform bucket-level access. |
| `Sql` | SQL-001 to SQL-004 | Public IP, 0.0.0.0/0, encrypted connections, backups. |
| `OrgPolicy` | ORG-001 to ORG-009 | Effective organization policies (inherited ones count). |
| `Kms` (opt-in) | KMS-001, KMS-002 | Public keys, rotation. Only the `--kms-location` locations are scanned. |

[`Docs/Coverage.md`](Docs/Coverage.md) lists every check with its severity and framework mappings, and what is not covered yet (inherited
organisation settings, BigQuery, GKE, Cloud Run / Functions and others).

## Permissions

Everything is read with the account active in gcloud (or the service account you impersonate). A role you do not hold turns the affected
checks into *NotAssessed*; it never fails the run.

| Need | Role (project level) |
|---|---|
| Most checks | Viewer (`roles/viewer`) and Security Reviewer (`roles/iam.securityReviewer`) |
| ORG-001 to ORG-009 | Organization Policy Viewer (`roles/orgpolicy.policyViewer`) |
| IAM-010, IAM-011 | API Keys Viewer (`roles/serviceusage.apiKeysViewer`) |
| KMS domain | Cloud KMS Viewer (`roles/cloudkms.viewer`) |
| `--folder-id` / `--organization-id` | Browser (`roles/browser`) on that folder or organisation |

To use `--impersonate-service-account`, create a service account with these roles and grant yourself Service Account Token Creator on it; no
key is ever created. These role lists reflect Google's documented role contents and have not been confirmed on a live project yet.

## How a run works

1. `connect` finds `gcloud`, reads the active account and, if asked, sets up impersonation.
2. The scope is resolved (`projects describe`); folders and organisations expand to the projects directly under them.
3. The elevated-account guard warns if the account can change resources.
4. Each domain runs once per project. A failure inside one project turns that project's checks into *NotAssessed*; other projects carry on.
5. The per-project results of each check are merged into one finding (`merged_status` in `model.py` holds the rule for mixed results), then
   accepted risks are applied, the score is calculated and the reports are written.

## Accepted risks

```json
{ "risks": [ { "findingId": "LOG-002", "reason": "Aggregated sink is set on the organisation", "approvedBy": "J. Smith", "expires": "2027-06-30",
               "affected": ["my-project-id - no enabled sink exports all log entries"] } ] }
```

Pass the file with `--accepted-risk-path`. `affected` is optional (omit it to accept the whole finding); every affected object must be
covered or the finding stays a Gap. An expired acceptance stops applying. Files named `*accepted*.json` are git-ignored.

## Your data

Reports contain real information about your projects (project IDs, principals, resource names). `GcpAssessment/` and `Assessments/` are in
`.gitignore` so they are not committed by accident, and no project ID or credential is stored in the code. The tool makes no network calls
other than the ones `gcloud` makes to Google. On macOS and Linux the report folder is restricted to your user.

## Status and limits

Verified two ways: an offline test suite that replaces gcloud with fixtures (93 tests), and one live run against a newly created, empty
project (IAM, logging, organization-policy and API-key checks read real data; Compute, Cloud SQL, Storage, DNS and Cloud KMS were not
exercised live because that project had none of those resources). **Those checks have only been tested against the documented shapes of
gcloud's output.** A field gcloud names differently shows up as *NotAssessed* rather than a wrong answer, but expect some first-run tuning on
a project that uses them. Only macOS has been used so far; CI runs the suite on Linux, macOS and Windows.

Treat the output as a review aid, not an audit: the checks follow published guidance, some only approximate a recommendation, and a pass
means the setting that was read looks right, not that the project is secure. CIS numbers follow v3.0.0 and should be confirmed against the
edition you hold.

## Layout: one file per domain, one function per check

```
google_gap_assessment/
  checks/
    iam.py            IAM-001..011     one function per check, registered in CHECKS
    audit_logging.py  LOG-001..003
    network.py        NET-001..008
    compute.py        CMP-001..008
    storage.py        STO-001..002
    sql.py            SQL-001..004
    kms.py            KMS-001..002     (opt-in)
    orgpolicy.py      ORG-001..009     one row per constraint in CHECKS_TABLE
    common.py         Check, registrar, run_checks, IAM vocabulary
  data/control_mapping.json            name, severity, SCF, NIST CSF, CIS, remediation per id
tests_python/checks/  test_iam.py ...  one test file per domain, plus test_registry.py
```

Each check is a short function with a docstring saying what it tests, for example `iam.py: public_principals` is `IAM-003`.
`python3 -m google_gap_assessment --list-checks` prints the id, domain, severity and name of every check.

## Redo a specific check

An auditor or admin asks for one check to be repeated after a fix? Run just that check; only the domain that owns it is touched and
only the data it needs is read. The report is labelled **PARTIAL ASSESSMENT** so it cannot be mistaken for a full one.

```bash
python3 -m google_gap_assessment --project-id my-project-id --check IAM-003 CMP-005
```

To change how a check decides, edit its function in the domain file and its case in the matching `tests_python/checks/test_<domain>.py`
(search for the id). To change its wording, severity or remediation, edit `data/control_mapping.json`.

## Tests and extending

```bash
python3 -m unittest discover -s tests_python -t .     # offline, well under a second
python3 -m unittest tests_python.checks.test_iam      # one domain
python3 -m google_gap_assessment.coverage                # regenerate Docs/Coverage.md after changing the mapping
```

To add a check: (1) add it to `google_gap_assessment/data/control_mapping.json` (id, domain, name, severity, SCF, NIST CSF, CIS, remediation;
ids are never reused); (2) in the domain module, add a function decorated with `@check("XXX-000")` that returns
`gap_or_pass(...)` built from `ctx.gcloud.get_list("<read-only command>", ...)`, using only `list`, `describe` and `get-iam-policy`;
(3) return `NotAssessed`, never `Pass`, for any field gcloud did not return; (4) add a case to the domain's test file. The registry tests fail
if a mapped id has no function, a function has no docstring, or an id is registered twice.

## Licence

[MIT](LICENSE).
