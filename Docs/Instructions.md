# Running the Google Assessor: instructions for administrators

This guide is for the person who will run the assessment: an IT administrator, or a consultant working for one. It covers the one-time
setup, a run, reading the results, and what to do when something goes wrong. For what each check does, see
[`Coverage.md`](Coverage.md). For the design and its limits, see the [README](../README.md).

**The tool only reads.** It never changes a setting, user, file or resource. It does not read mail, files or calendar contents.

---

## 1. Before you start

| You need | Why |
|---|---|
| **Python 3.11 or later** (`python3 --version`) | The tool is plain Python with no packages to install |
| **A web browser** on the same computer | You sign in with it |
| **A Google Workspace Super Admin account** (Workspace checks) | Google has no read-only admin role that can read every setting, so a Super Admin has to sign in. Use a dedicated admin account with 2-step verification, not a shared one |
| **The Google Cloud CLI, `gcloud`** (Google Cloud checks only) | Cloud checks run through it. [Install it](https://cloud.google.com/sdk/docs/install), then `gcloud auth login` |
| **Viewer and Security Reviewer on the projects** (Google Cloud checks only) | A read-only account is enough. Roles for individual checks are listed in the README |

Get the tool and always run it from its folder:

```bash
git clone https://github.com/rhysetherington/google-assessor.git
cd google-assessor
```

> **If you see `No module named google_gap_assessment`, you are not in the tool's folder.** Run `cd` into it first.

---

## 2. One-time setup for Google Workspace

The tool signs the Super Admin in itself, using an "OAuth client" that you create once, in a Google Cloud project you control. Allow
about ten minutes. `python3 -m google_gap_assessment --setup-help` prints a short version of these steps.

Do every step below **signed in as the same Workspace admin account**. The Google Cloud project belongs to whoever creates it, and only
that account (or someone with rights on the project) can switch APIs on for it.

1. **Create or choose a Google Cloud project** at <https://console.cloud.google.com>. Any name will do. It must belong to the same
   Workspace organisation as the tenant you are assessing, because the next steps use the "Internal" setting. Note its **project ID**.
2. **Enable two APIs in that project**: *Admin SDK API* and *Cloud Identity API* (APIs & Services > Library).
   Or from a terminal signed in as the project's owner:
   ```bash
   gcloud services enable admin.googleapis.com cloudidentity.googleapis.com --project YOUR_PROJECT_ID
   ```
   If you skip this, the run completes but nearly every check says "not assessed" (see Troubleshooting).
3. **OAuth consent screen** (APIs & Services > OAuth consent screen): choose user type **Internal**, give the app a name and your
   e-mail address, and save. You do not need to add scopes by hand.
4. **Create the client** (APIs & Services > Credentials > Create credentials > OAuth client ID): type **Desktop app**. Download the
   JSON file.
5. **Keep the file out of any git folder** and restrict it to yourself, for example:
   ```bash
   mkdir -p ~/.config && mv ~/Downloads/client_secret_*.json ~/.config/client_secret.json && chmod 600 ~/.config/client_secret.json
   ```
   The file identifies your app; treat it like a configuration secret and do not email it around.

You do this once per Google Cloud project. Later runs, including for other client tenants, can reuse the same file provided the
tenant is in the same organisation. For a tenant in a different organisation, create a project and client there (an "Internal" client
only works for the organisation that owns it).

---

## 3. Running an assessment

```bash
python3 -m google_gap_assessment
```

It asks what to assess:

1. Google Workspace only
2. Google Workspace and Google Cloud
3. Google Cloud only

For Workspace, add the client file so the tool can sign you in:

```bash
python3 -m google_gap_assessment --scope workspace --oauth-client-file ~/.config/client_secret.json
```

What happens:

1. Your browser opens. **Sign in as the Super Admin** and approve the read-only permissions (it asks only for viewing users, groups,
   domains, admin roles, reports and settings).
2. The tool collects the nine Workspace areas: Identity, Gmail, Drive, Groups, Meet, Calendar, Chat, Classroom and Sites.
3. It asks for the report details: client name, assessment name, assessor, date and an optional reference. Press Enter to accept
   each default.
4. The sign-in is **revoked**, and you see "Signed out".
5. It prints the score and writes the reports.

Useful options:

| Option | What it does |
|---|---|
| `--scope workspace`, `both`, `cloud` | Skip the menu |
| `--no-dns` | Skip the SPF, DKIM, DMARC, MTA-STS and TLS-RPT lookups. **Without this flag, the tenant's domain names are sent to a public DNS resolver (Cloudflare by default).** Those 8 checks are then reported as "not assessed" |
| `--doh-endpoint URL` | Use a different DNS-over-HTTPS resolver |
| `--no-prompt` | Do not ask for report details (use this in scripts) |
| `--client-name`, `--assessor-name`, `--assessment-date`, `--reference` | Give the report details up front |
| `--brand-color "#RRGGBB"` | Accent colour for the HTML report |
| `--include-evidence` | Also write one CSV per finding listing every affected user, group or resource |
| `--export-path FOLDER` | Where reports go (default `./GoogleAssessment`) |
| `--check GID-005 GML-028` | Redo only those checks (see section 6) |
| `--list-checks` | List every check id, severity and name |

### Google Cloud checks

```bash
gcloud auth login
python3 -m google_gap_assessment --scope cloud --project-id my-project-id
```

Use `--folder-id` or `--organization-id` instead of `--project-id` to assess the projects under a folder or organisation. Use a
read-only account (or `--impersonate-service-account`); if the account can change resources the tool warns you and asks to confirm.

### Both together

```bash
python3 -m google_gap_assessment --scope both --oauth-client-file ~/.config/client_secret.json --project-id my-project-id
```

---

## 4. The reports

Every run writes three files, in `GoogleAssessment/<ClientName>-<date>/` (a time such as `-2110` is added when the folder already exists):

| File | For |
|---|---|
| `…-Assessment.html` | **The client.** One self-contained page (no internet needed) with the score, a summary, every gap and the remediation steps. Open it in a browser or send it as is |
| `…-Assessment.md` | Pasting into tickets, wikis or a document |
| `…-Findings.json` | Machines, and re-rendering later without signing in again |

**These files contain real information about the tenant** (domains, user e-mail addresses, group names). Store and share them like any
other confidential client document. The folder is readable only by your user and is excluded from git.

### What the results mean

| Status | Meaning |
|---|---|
| **Pass** | The setting was read and looks right |
| **Gap** | The setting was read and is weaker than the recommendation. The report says what to change and how |
| **NotAssessed** | The tool could not read the setting (a permission, an edition that lacks it, a switched-off option such as `--no-dns`, or Google returned no value). **It counts against the score, never as a pass**, so the score is not flattering |
| **NotApplicable** | The product is off or unused, so there is nothing to misconfigure |
| **Accepted** | A gap that you recorded as a knowingly accepted risk (section 7) |

The score weights severity (Critical 10, High 5, Medium 3, Low 1). Read it as a trend to improve, not a grade: **a brand-new tenant on
Google's defaults scores low**, because several defaults (for example, 2-step verification not enforced) are weaker than recommended.

**Before you give a report to a client, check how many checks are NotAssessed and why.** A large number usually means a setup problem
(section 8), not a clean tenant. The tool's output is a review aid. It follows published guidance (CISA SCuBA and CIS), some checks only
approximate a recommendation, and a pass means the setting that was read looks right, not that the tenant is secure.

---

## 5. After the run

* **The sign-in is already revoked.** The tool holds the token in memory only and never writes it to disk. You can confirm under the
  admin account's *Security > Third-party apps with account access* page.
* Keep or delete `~/.config/client_secret.json` as you see fit. It cannot read anything without a person signing in.
* To disable the tool entirely, delete the OAuth client in the Cloud Console.
* Send the HTML report to the client by a channel suitable for confidential documents.

---

## 6. Redoing one check

Auditors and administrators often ask for one item to be re-checked after a fix:

```bash
python3 -m google_gap_assessment --list-checks
python3 -m google_gap_assessment --check GML-028 GID-005 --oauth-client-file ~/.config/client_secret.json
```

Only the areas that own those checks run, and only that data is read. The report is stamped **PARTIAL ASSESSMENT** so it cannot be
mistaken for a full one.

---

## 7. Recording accepted risks

If a client knowingly keeps a setting, record it so the report shows it as Accepted and not as an open gap:

```json
{ "risks": [ { "findingId": "GML-033", "reason": "Partner allowlist reviewed quarterly", "approvedBy": "J. Smith", "expires": "2027-06-30" } ] }
```

Save it as, for example, `accepted-risks.json` and run with `--accepted-risk-path accepted-risks.json`. An acceptance stops applying
on its `expires` date.

---

## 8. Troubleshooting

| What you see | Cause and fix |
|---|---|
| `No module named google_gap_assessment` | You are not in the tool's folder. `cd` into the cloned `google-assessor` folder |
| Almost every Workspace check is NotAssessed, with "Cloud Identity API has not been used in project … or it is disabled" | The two APIs are not enabled in the OAuth client's project (setup step 2). Enable them **as the account that owns the project**, wait a minute or two, and run again |
| `Permission denied to enable service` when running `gcloud services enable` | `gcloud` is signed in as an account with no rights on that project. Enable the APIs in the Cloud Console as the project's owner instead |
| The browser says the app is blocked, or "access denied" | The consent screen is not **Internal**, or the signed-in account is not in the organisation that owns the project. Sign in as a Super Admin of that tenant |
| `The access token has none of the read-only Workspace scopes` | You used a plain `gcloud` sign-in. Use `--oauth-client-file` (section 2) |
| A warning that the sign-in "can do more than read" | A `gcloud auth application-default login` token is being used. It carries the broad `cloud-platform` permission. Revoke it with `gcloud auth application-default revoke` and use `--oauth-client-file` |
| `HTTP 403 … insufficient` or a permission error for some checks | The account is not a Super Admin, or a scope was not granted. Sign in as a Super Admin and approve every permission |
| Email checks (DKIM, SPF, DMARC, MTA-STS, TLS-RPT) are NotAssessed | You used `--no-dns`. Run again without it |
| "Google returned no value for settings/…" on a few checks | The setting has never been changed, or the edition does not include it, and Google leaves it out. The tool only treats a missing value as a default where Google documents that default; otherwise it stays NotAssessed |
| Cloud checks say the gcloud account has Owner or Editor | Use a Viewer plus Security Reviewer account, or `--impersonate-service-account`. Pass `--allow-elevated-account` only if you accept running as that account |
| `gcloud` not found | Install the Google Cloud CLI and make sure it is on your PATH |

If a problem is not listed, run with the failing check only (`--check ID`) and read the *Detail* column for that finding. It carries
the exact reason.

---

## 9. What leaves your computer

* **To Google**, read-only requests to the Admin SDK and Cloud Identity APIs (and to Google Cloud through `gcloud`).
* **To a DNS resolver** (Cloudflare unless you change it with `--doh-endpoint`), the tenant's **domain names**, to read its SPF, DKIM,
  DMARC, MTA-STS and TLS-RPT records. Use `--no-dns` to avoid this.
* Nothing else. There is no telemetry, and reports and tokens are not uploaded anywhere.

---

## 10. Quick checklist

- [ ] Python 3.11+, cloned the repo, `cd` into it
- [ ] Project with **Admin SDK API** and **Cloud Identity API** enabled
- [ ] OAuth consent screen **Internal**, Desktop client JSON saved at `~/.config/client_secret.json` (mode 600)
- [ ] Run as a Workspace **Super Admin** (dedicated account, 2-step verification on)
- [ ] Run **without** `--no-dns` if the client agrees to domain lookups
- [ ] Check the NotAssessed count and reasons before sharing
- [ ] Share the HTML report securely; keep the folder confidential
