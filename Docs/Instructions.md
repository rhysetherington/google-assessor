# Running the Google Assessor: instructions for administrators

This guide is for the person who will use the tool: an IT administrator, or a consultant working for one. It covers the one-time setup,
the two commands (run an assessment, compare two assessments), reading the results, and what to do when something goes wrong. For what
each check does, see [`Coverage.md`](Coverage.md). For the design and its limits, see the [README](../README.md).

**The tool only reads.** It never changes a setting, user, file or resource. It does not read mail, files or calendar contents.

## The two commands at a glance

Always run them from the tool's folder.

| | Command | What it does | Needs a sign-in? |
|---|---|---|---|
| **1** | `python3 -m google_gap_assessment` | **Runs an assessment** of your Google Workspace and/or Google Cloud and writes the reports | Yes (a Workspace Super Admin, and/or gcloud) |
| **2** | `python3 -m google_gap_assessment compare` | **Compares two saved assessments**, earlier on the left and later on the right. You choose the one to start from | No. It only reads reports already on your computer |

Typical use: run command 1 for a baseline, let the client fix things, run command 1 again, then run command 2 to show the progress.

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
about ten minutes. `python3 -m google_gap_assessment --setup-help` prints a short version of these steps. (Skip this section if you only
assess Google Cloud, or only use command 2.)

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

## 3. Command 1: run an assessment

### Step by step (Google Workspace)

1. Open a terminal and go to the tool's folder: `cd google-assessor`
2. Run:
   ```bash
   python3 -m google_gap_assessment --scope workspace --oauth-client-file ~/.config/client_secret.json
   ```
   (Without `--scope` it first asks: 1) Google Workspace only, 2) Google Workspace and Google Cloud, 3) Google Cloud only.)
3. **Your browser opens.** Sign in as the Super Admin and approve the read-only permissions. It asks only for viewing users, groups,
   domains, admin roles, reports and settings.
4. The terminal shows progress as it collects the nine Workspace areas: Identity, Gmail, Drive, Groups, Meet, Calendar, Chat, Classroom
   and Sites.
5. It asks for the **report details**: client name, assessment name, assessor, date and an optional reference. Press Enter to accept each
   default. (Use a consistent client name each time, because it names the report folder.)
6. The sign-in is **revoked** and you see "Signed out".
7. It prints the score and lists the files it wrote, for example:
   ```
   Score 41.5%  |  108 checks: 49 passed, 47 gaps, 12 not assessed, 0 accepted
     wrote GoogleAssessment/Acme-2026-10-29/Acme-2026-10-29-Findings.json
     wrote GoogleAssessment/Acme-2026-10-29/Acme-2026-10-29-Assessment.md
     wrote GoogleAssessment/Acme-2026-10-29/Acme-2026-10-29-Assessment.html
   ```
8. **Check the "not assessed" number before you share anything** (section 4). A high number usually means a setup problem.

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

### Options

| Option | What it does |
|---|---|
| `--scope workspace`, `both`, `cloud` | Skip the menu |
| `--no-dns` | Skip the SPF, DKIM, DMARC, MTA-STS and TLS-RPT lookups. **Without this flag, the tenant's domain names are sent to a public DNS resolver (Cloudflare by default).** Those 8 checks are then reported as "not assessed" |
| `--doh-endpoint URL` | Use a different DNS-over-HTTPS resolver |
| `--no-prompt` | Do not ask for report details (use this in scripts) |
| `--client-name`, `--assessment-name`, `--assessor-name`, `--assessment-date`, `--reference` | Give the report details up front |
| `--brand-color "#RRGGBB"` | Accent colour for the HTML report |
| `--logo FILE` | Put your or your client's logo (`.png`, `.jpg`, `.gif`, `.webp` or `.svg`, up to 400 KB) in the HTML report header. The image is embedded, so the report stays one file |
| `--include-evidence` | Also write one CSV per finding listing every affected user, group or resource |
| `--export-path FOLDER` | Where reports go (default `./GoogleAssessment`) |
| `--accepted-risk-path FILE` | Record knowingly accepted risks (section 7) |
| `--compare-with FILE` | Also compare the new run with an earlier one in one step (see command 2) |
| `--check GID-005 GML-028` | Redo only those checks (below) |
| `--list-checks` | List every check id, severity and name |

### Redoing one check

Auditors and administrators often ask for one item to be re-checked after a fix:

```bash
python3 -m google_gap_assessment --list-checks
python3 -m google_gap_assessment --check GML-028 GID-005 --oauth-client-file ~/.config/client_secret.json
```

Only the areas that own those checks run, and only that data is read. The report is stamped **PARTIAL ASSESSMENT** so it cannot be
mistaken for a full one, and it is marked **[PARTIAL]** in the comparison list.

---

## 4. The reports and what they mean

Every run writes three files, in `GoogleAssessment/<ClientName>-<date>/` (a time such as `-2110` is added when the folder already exists):

| File | For |
|---|---|
| `…-Assessment.html` | **The client.** One self-contained page (no internet needed) with an executive summary, charts, a heat-map of areas, every gap and the remediation steps. Open it in a browser or send it as is |
| `…-Assessment.md` | Pasting into tickets, wikis or a document |
| `…-Findings.json` | Machines, comparing later (command 2) and re-rendering without signing in again |

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

## 5. Command 2: compare two assessments

Use this to show progress: what the client fixed, what got worse, and what is still open. It reads only the reports already saved on your
computer, so it needs **no sign-in** and sends nothing anywhere.

### Step by step

1. Make sure you have **at least two saved assessments** (run command 1 twice). Reports are kept under `GoogleAssessment/`.
2. Open a terminal and go to the tool's folder: `cd google-assessor`
3. Run:
   ```bash
   python3 -m google_gap_assessment compare
   ```
4. **Choose the assessment to start from.** It lists your saved assessments, newest first, with date, client, score, number of checks and
   scope:
   ```
   Saved assessments under GoogleAssessment (newest first):
      1) 2026-10-29  Acme  |  Second Gap Assessment  |  41.5%, 108 checks, Workspace  (Acme-2026-10-29)
      2) 2026-10-25  Acme  |  First Gap Assessment   |  36.3%, 108 checks, Workspace  (Acme-2026-10-25)
   Start from which assessment? Enter its number: 2
   ```
5. **Choose what to compare it with.** Only assessments later than your starting point are listed. Press Enter to accept the most recent:
   ```
   Compare it with:
      1) 2026-10-29  Acme  |  Second Gap Assessment  |  41.5%, 108 checks, Workspace  (Acme-2026-10-29)
   Number of the assessment to compare with [1]:
   ```
6. It prints a one-line summary and the path of the page it wrote:
   ```
   Score 36.3% -> 41.5% | fixed 4, got worse 1, still open 46, newly assessed 1
     wrote GoogleAssessment/Acme-2026-10-29/Acme-2026-10-29-Comparison-from-Acme-2026-10-25.html
   ```
7. Open that `.html` file in a browser.

If you pick the two the wrong way round, the tool swaps them so the earlier assessment is always on the left.

### Other ways to run it

| Command | Result |
|---|---|
| `compare --list` | Show the saved assessments and stop |
| `compare FOLDER_OR_FINDINGS_JSON` | Compare that one with the most recent, without asking |
| `compare BEFORE AFTER` | Compare two you name (a report folder or its `…-Findings.json`) |
| `compare --root OTHER_FOLDER` | Look for assessments somewhere other than `./GoogleAssessment` |
| `compare --out FILE` | Write the page somewhere specific |
| `assess … --compare-with FILE` | Run a new assessment **and** compare it with `FILE` in one step |

### Reading the comparison page

The top shows the earlier assessment on the left, the later one on the right, and the change in score between them. Below, checks are
grouped by what happened, most important first:

| Section | Meaning |
|---|---|
| **Got worse** | Passed before, a gap now. Look at these first |
| **Fixed** | Gaps that are now closed |
| **Still a gap, more / fewer affected** | The gap remains and affects more or fewer accounts than before |
| **Now assessed** / **No longer assessed** | The check could not be read in one run but could in the other |
| **Only in the later / earlier run** | The check was not part of one of the assessments |
| **Still open, unchanged** and **Unchanged** | No change (collapsed by default) |

If the later run could read more checks than the earlier one, the score moves for that reason too, so read **Now assessed** alongside the
score change.

### Choose a trustworthy starting point

A comparison is only as good as the assessment it starts from. Before you pick one:

* Open its report and check the **Could not be assessed** count. A run where most checks could not be read (for example, a first run
  before the Admin SDK and Cloud Identity APIs were enabled) scores very low for that reason, not because the tenant is weak.
  Comparing against it makes later results look better than they are.
* Runs made with an earlier, faulty version of the tool, or while setup was incomplete, should not be used as a baseline.
* The list shows every folder under `GoogleAssessment/`. To keep it clean, **move** unreliable runs out (for example into
  `GoogleAssessment-archive/`) rather than deleting them. `compare` only looks inside the folder given by `--root`.
* Compare against the run that best matches the question you are asking, such as "what changed since the last review" or "what changed
  since the engagement began".

---

## 6. After a run

* **The sign-in is already revoked.** The tool holds the token in memory only and never writes it to disk. You can confirm under the
  admin account's *Security > Third-party apps with account access* page.
* Keep or delete `~/.config/client_secret.json` as you see fit. It cannot read anything without a person signing in.
* To disable the tool entirely, delete the OAuth client in the Cloud Console.
* Send the HTML report to the client by a channel suitable for confidential documents.

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
| `compare` says there are fewer than two saved assessments | It looks in `./GoogleAssessment` of the folder you run it from. `cd` into the tool's folder, or point at yours with `--root` |
| `compare` says the one you picked is the most recent | Nothing is later than it to compare with. Pick an earlier one as the starting point |
| A domain ending `.test-google-a.com` is listed under the tenant's domains | Google creates that receive-only test alias for every Workspace tenant. It cannot send mail, so the SPF, DKIM, DMARC, MTA-STS and TLS-RPT checks skip it. It is listed for completeness only |
| Email checks (DKIM, SPF, DMARC, MTA-STS, TLS-RPT) are NotAssessed | You used `--no-dns`. Run again without it |
| "Google returned no value for settings/…" on a few checks | The setting has never been changed, or the edition does not include it, and Google leaves it out. The tool only treats a missing value as a default where Google documents that default; otherwise it stays NotAssessed |
| Cloud checks say the gcloud account has Owner or Editor | Use a Viewer plus Security Reviewer account, or `--impersonate-service-account`. Pass `--allow-elevated-account` only if you accept running as that account |
| `gcloud` not found | Install the Google Cloud CLI and make sure it is on your PATH |

If a problem is not listed, run with the failing check only (`--check ID`) and read the *Detail* column for that finding. It carries
the exact reason.

---

## 9. What leaves your computer

* **To Google**, read-only requests to the Admin SDK and Cloud Identity APIs (and to Google Cloud through `gcloud`). Command 1 only.
* **To a DNS resolver** (Cloudflare unless you change it with `--doh-endpoint`), the tenant's **domain names**, to read its SPF, DKIM,
  DMARC, MTA-STS and TLS-RPT records. Use `--no-dns` to avoid this. Command 1 only.
* Nothing else. There is no telemetry, reports and tokens are not uploaded anywhere, and command 2 makes no network requests.

---

## 10. Quick checklist

**Before command 1 (assess)**

- [ ] Python 3.11+, cloned the repo, `cd` into it
- [ ] Project with **Admin SDK API** and **Cloud Identity API** enabled
- [ ] OAuth consent screen **Internal**, Desktop client JSON saved at `~/.config/client_secret.json` (mode 600)
- [ ] Run as a Workspace **Super Admin** (dedicated account, 2-step verification on)
- [ ] Run **without** `--no-dns` if the client agrees to domain lookups
- [ ] Check the NotAssessed count and reasons before sharing
- [ ] Share the HTML report securely; keep the folder confidential

**Before command 2 (compare)**

- [ ] At least two saved assessments under `GoogleAssessment/`
- [ ] The starting assessment is a valid one (low NotAssessed count, run with a working setup); archive any that are not
- [ ] Read **Now assessed** next to the score change
