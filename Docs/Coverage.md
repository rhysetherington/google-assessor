# Coverage

Generated from `google_gap_assessment/data/control_mapping.json` by `python3 -m google_gap_assessment.coverage`; do not edit by hand. 155 checks.

## Google Workspace (108 checks)

SCuBA references are the CISA Secure Cloud Business Applications baseline policies each check covers (`COMMONCONTROLS.5.2` is `GWS.COMMONCONTROLS.5.2v1`); a check with `-` is an addition of our own.

### Workspace: Calendar

| ID | Check | Severity | CISA SCuBA | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| GCL-001 | Primary calendars show outsiders more than free/busy | Medium | CALENDAR.1.1 | PR.DS-01 | DCH-14 |
| GCL-002 | Secondary calendars show outsiders more than free/busy | Medium | CALENDAR.1.2 | PR.DS-01 | DCH-14 |
| GCL-003 | Users are not warned when inviting people outside the organisation | Low | CALENDAR.2.1 | PR.DS-01 | DCH-14 |
| GCL-004 | Calendar interoperability is enabled | Low | CALENDAR.3.1 | PR.PS-01 | CFG-03 |
| GCL-005 | Appointment schedules can take payments | Low | CALENDAR.4.1 | PR.PS-01 | CFG-03 |

### Workspace: Chat

| ID | Check | Severity | CISA SCuBA | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| GCH-001 | Chat history is not on by default | Medium | CHAT.1.1 | PR.PS-04 | MON-10 |
| GCH-002 | Users can change their chat history setting | Medium | CHAT.1.2 | PR.PS-04 | MON-10 |
| GCH-003 | Files can be shared with people outside the organisation in Chat | Medium | CHAT.2.1 | PR.DS-01 | DCH-14 |
| GCH-004 | Space history is not always on | Low | CHAT.3.1 | PR.PS-04 | MON-10 |
| GCH-005 | External chat is not limited to allowlisted domains | Medium | CHAT.4.1 | PR.IR-01 | NET-12 |

### Workspace: Classroom

| ID | Check | Severity | CISA SCuBA | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| GCR-001 | Outsiders can join classes | Low | CLASSROOM.1.1 | PR.AA-05 | IAC-20 |
| GCR-002 | Users can join classes run by other organisations | Low | CLASSROOM.1.2 | PR.AA-05 | IAC-20 |
| GCR-003 | Users can authorise apps to access Classroom data | Medium | CLASSROOM.2.1 | PR.AA-05 | IAC-20 |
| GCR-004 | Roster import is enabled | Low | CLASSROOM.3.1 | PR.PS-01 | CFG-03 |
| GCR-005 | Students can unenrol other students | Low | CLASSROOM.4.1 | PR.AA-05 | IAC-20 |
| GCR-006 | Anyone can create classes | Low | CLASSROOM.5.1 | PR.AA-05 | IAC-20 |

### Workspace: Drive and Docs

| ID | Check | Severity | CISA SCuBA | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| GDR-001 | Files can be shared with anyone outside the organisation | High | DRIVEDOCS.1.1 | PR.DS-01 | DCH-14 |
| GDR-002 | Users can receive files from outside the sharing boundary | Medium | DRIVEDOCS.1.2 | PR.DS-01 | DCH-14 |
| GDR-003 | Users are not warned before sharing outside the organisation | Low | DRIVEDOCS.1.3 | PR.DS-01 | DCH-14 |
| GDR-004 | Users can invite people without Google accounts | Medium | DRIVEDOCS.1.4 | PR.AA-03 | IAC-02 |
| GDR-005 | Users can publish files to the web | High | DRIVEDOCS.1.5 | PR.DS-01 | DCH-14 |
| GDR-006 | Access-checker suggestions offer wider audiences than the recipients | Low | DRIVEDOCS.1.6 | PR.DS-01 | DCH-14 |
| GDR-007 | Content can be distributed to shared drives outside the organisation | Medium | DRIVEDOCS.1.7 | PR.DS-01 | DCH-14 |
| GDR-008 | New files are shared by link by default | Medium | DRIVEDOCS.1.8 | PR.DS-01 | DCH-14 |
| GDR-009 | Files from outside the organisation are not highlighted | Low | DRIVEDOCS.1.9 | PR.DS-01 | DCH-14 |
| GDR-010 | Shared drive managers can override sharing settings | Medium | DRIVEDOCS.2.1 | PR.AA-05 | IAC-20 |
| GDR-011 | Shared drives can be shared with people outside the organisation | Medium | - | PR.DS-01 | DCH-14 |
| GDR-012 | The Drive link-security update is not applied or users can remove it | Medium | DRIVEDOCS.3.1 | PR.DS-01 | DCH-14 |
| GDR-013 | Drive SDK access is enabled | Medium | DRIVEDOCS.4.1 | PR.PS-01 | CFG-03 |
| GDR-014 | Drive for desktop is not limited to authorised devices | Medium | DRIVEDOCS.5.1 | PR.PS-01 | END-01 |

### Workspace: Gmail and email security

| ID | Check | Severity | CISA SCuBA | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| GML-001 | Mailbox delegation is allowed | Medium | GMAIL.1.1 | PR.AA-05 | IAC-21 |
| GML-002 | DKIM is not published for every domain | High | GMAIL.2.1 | PR.IR-01 | NET-12 |
| GML-003 | SPF does not hard-fail unauthorised senders | High | GMAIL.3.1 | PR.IR-01 | NET-12 |
| GML-004 | DMARC is not published for every domain | High | GMAIL.4.1 | PR.IR-01 | NET-12 |
| GML-005 | DMARC policy is not reject | High | GMAIL.4.2 | PR.IR-01 | NET-12 |
| GML-006 | DMARC aggregate reporting is not configured | Medium | GMAIL.4.4 | DE.CM-01 | NET-12 |
| GML-007 | DMARC applies to only part of the mail | Medium | - | PR.IR-01 | NET-12 |
| GML-008 | MTA-STS is not published | Low | - | PR.DS-02 | CRY-03 |
| GML-009 | TLS reporting is not published | Low | - | DE.CM-01 | CRY-03 |
| GML-010 | Protection against encrypted attachments is off | Medium | GMAIL.5.1 | DE.CM-09 | END-04 |
| GML-011 | Protection against attachments with scripts is off | Medium | GMAIL.5.2 | DE.CM-09 | END-04 |
| GML-012 | Protection against anomalous attachment types is off | Medium | GMAIL.5.3 | DE.CM-09 | END-04 |
| GML-013 | Future recommended attachment protections are not applied automatically | Low | GMAIL.5.4 | DE.CM-09 | END-04 |
| GML-014 | Suspicious attachments stay in the inbox | Medium | GMAIL.5.5 | DE.CM-09 | END-04 |
| GML-015 | Links behind shorteners are not scanned | Medium | GMAIL.6.1 | DE.CM-09 | END-04 |
| GML-016 | Images from external senders are not scanned | Medium | GMAIL.6.2 | DE.CM-09 | END-04 |
| GML-017 | Aggressive warnings on untrusted links are off | Low | GMAIL.6.3 | DE.CM-09 | END-04 |
| GML-018 | Future link and image protections are not applied automatically | Low | GMAIL.6.4 | DE.CM-09 | END-04 |
| GML-019 | Domain-name spoofing protection is off | High | GMAIL.7.1 | PR.IR-01 | NET-12 |
| GML-020 | Employee-name spoofing protection is off | High | GMAIL.7.2 | PR.IR-01 | NET-12 |
| GML-021 | Protection against your domain being spoofed is off | High | GMAIL.7.3, GMAIL.7.5 | PR.IR-01 | NET-12 |
| GML-022 | Unauthenticated email is not flagged | Medium | GMAIL.7.4 | PR.IR-01 | NET-12 |
| GML-023 | Spoofed email is left in the inbox | Medium | GMAIL.7.6 | PR.IR-01 | NET-12 |
| GML-024 | Future spoofing protections are not applied automatically | Low | GMAIL.7.7 | PR.IR-01 | NET-12 |
| GML-025 | Users can import email from other providers | Low | GMAIL.8.1 | PR.DS-01 | NET-12 |
| GML-026 | POP or IMAP access is enabled | High | GMAIL.9.1 | PR.AA-03 | IAC-02 |
| GML-027 | Google Workspace Sync for Microsoft Outlook is enabled | Low | GMAIL.10.1 | PR.PS-01 | CFG-03 |
| GML-028 | Users can automatically forward email outside the organisation | High | GMAIL.11.1 | PR.DS-01 | NET-12 |
| GML-029 | Users can send mail through their own SMTP servers | Medium | GMAIL.12.1 | PR.IR-01 | NET-12 |
| GML-030 | The spam-filter IP allowlist is not empty | High | GMAIL.14.1 | PR.IR-01 | NET-12 |
| GML-031 | Enhanced pre-delivery message scanning is off | Medium | GMAIL.15.1 | DE.CM-09 | END-04 |
| GML-032 | Comprehensive mail storage is not enabled | Medium | GMAIL.17.1 | PR.PS-04 | MON-10 |
| GML-033 | Spam-filter override (allowlist) rules exist | Medium | GMAIL.18.1, GMAIL.18.2 | PR.IR-01 | NET-12 |
| GML-034 | A rule hides warning banners for all senders on a list | Medium | GMAIL.18.3 | PR.IR-01 | NET-12 |

### Workspace: Groups

| ID | Check | Severity | CISA SCuBA | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| GGR-001 | Groups can be accessed from outside the organisation | Medium | GROUPS.1.1 | PR.AA-05 | DCH-14 |
| GGR-002 | Group owners can add external members | Medium | GROUPS.1.2 | PR.AA-05 | IAC-20 |
| GGR-003 | Group owners can let the public post to a group | Low | GROUPS.1.3 | PR.IR-01 | NET-12 |
| GGR-004 | Anyone in the organisation can create groups | Low | GROUPS.2.1 | PR.AA-05 | IAC-20 |
| GGR-005 | Conversations are visible to more than group members by default | Low | GROUPS.3.1 | PR.DS-01 | DCH-14 |
| GGR-006 | Groups can be hidden from the directory | Low | GROUPS.4.1 | ID.AM-02 | AST-02 |

### Workspace: Identity and access

| ID | Check | Severity | CISA SCuBA | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| GID-001 | 2-step verification is not enforced | Critical | COMMONCONTROLS.1.2 | PR.AA-03 | IAC-06 |
| GID-002 | Second factor is not phishing-resistant (passkeys / security keys only) | High | COMMONCONTROLS.1.1, COMMONCONTROLS.1.3 | PR.AA-03 | IAC-06 |
| GID-003 | New users have no, or too long, an enrolment window for 2-step verification | Medium | COMMONCONTROLS.1.4 | PR.AA-03 | IAC-06 |
| GID-004 | Users can trust a device to skip 2-step verification | Medium | COMMONCONTROLS.1.5 | PR.AA-03 | IAC-06 |
| GID-005 | Active users are not enrolled in 2-step verification | High | - | PR.AA-03 | IAC-06 |
| GID-006 | Web sessions last longer than 12 hours | Medium | COMMONCONTROLS.4.1 | PR.AA-03 | IAC-25 |
| GID-007 | Password strength is not enforced as Strong | Medium | COMMONCONTROLS.5.1 | PR.AA-01 | IAC-10 |
| GID-008 | Minimum password length is below 12 | Medium | COMMONCONTROLS.5.2 | PR.AA-01 | IAC-10 |
| GID-009 | Minimum password length is below 16 (recommended) | Low | COMMONCONTROLS.5.3 | PR.AA-01 | IAC-10 |
| GID-010 | Password requirements are not enforced at the next sign-in | Medium | COMMONCONTROLS.5.4 | PR.AA-01 | IAC-10 |
| GID-011 | Users can reuse passwords | Low | COMMONCONTROLS.5.5 | PR.AA-01 | IAC-10 |
| GID-012 | Passwords expire on a schedule | Low | COMMONCONTROLS.5.6 | PR.AA-01 | IAC-10 |
| GID-013 | Too few or too many super admin accounts | High | COMMONCONTROLS.6.2 | PR.AA-05 | IAC-21 |
| GID-014 | Super admins sign in through an external identity provider | High | COMMONCONTROLS.6.1 | PR.AA-05 | IAC-21 |
| GID-015 | Administrator accounts are not enrolled in 2-step verification | Critical | - | PR.AA-03 | IAC-06 |
| GID-016 | Accounts that have not signed in for a long time are still active | Medium | - | PR.AA-01 | IAC-15 |
| GID-017 | Conflicting unmanaged accounts are preserved, not replaced | Medium | COMMONCONTROLS.7.1 | PR.AA-01 | IAC-15 |
| GID-018 | Super admins can recover their own accounts by self-service | Medium | COMMONCONTROLS.8.1 | PR.AA-01 | IAC-15 |
| GID-019 | Users can recover their own accounts by self-service | Low | COMMONCONTROLS.8.2 | PR.AA-01 | IAC-15 |
| GID-020 | Third-party app access to Google services is not restricted | High | COMMONCONTROLS.10.1 | PR.AA-05 | IAC-20 |
| GID-021 | Only high-risk scopes are restricted for Drive, Gmail, Classroom or Chat | Medium | COMMONCONTROLS.10.2 | PR.AA-05 | IAC-20 |
| GID-022 | Internal apps are trusted automatically | Medium | COMMONCONTROLS.10.3 | PR.AA-05 | IAC-20 |
| GID-023 | Users can access unreviewed third-party apps | High | COMMONCONTROLS.10.4 | PR.AA-05 | IAC-20 |
| GID-024 | Less secure app access is allowed | High | COMMONCONTROLS.10.5 | PR.AA-03 | IAC-02 |
| GID-025 | Marketplace apps are not restricted to an approved list | Medium | COMMONCONTROLS.11.1 | PR.PS-01 | CFG-03 |
| GID-026 | Google Takeout is enabled for users | Medium | COMMONCONTROLS.12.1 | PR.DS-01 | DCH-06 |
| GID-027 | Some system-defined alert rules are switched off | Medium | COMMONCONTROLS.13.1 | DE.CM-03 | MON-01 |
| GID-028 | Data at rest region is not pinned | Low | COMMONCONTROLS.15.1 | PR.DS-01 | DCH-01 |
| GID-029 | Data is not processed only in its storage region | Low | COMMONCONTROLS.15.2 | PR.DS-01 | DCH-01 |
| GID-030 | Multi-party approval is not enabled for sensitive admin changes | Medium | COMMONCONTROLS.17.1 | PR.AA-05 | IAC-21 |
| GID-031 | No active data-loss-prevention rules | Medium | COMMONCONTROLS.18.1, COMMONCONTROLS.18.2 | PR.DS-01 | DCH-01 |

### Workspace: Meet

| ID | Check | Severity | CISA SCuBA | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| GMT-001 | Outsiders who were not invited can join meetings without asking | Medium | MEET.1.1 | PR.AA-05 | IAC-20 |
| GMT-002 | Users can join meetings created outside any Workspace organisation | Medium | MEET.2.1 | PR.AA-05 | IAC-20 |
| GMT-003 | Host management features are off | Low | MEET.3.1 | PR.AA-05 | IAC-20 |
| GMT-004 | External participants are not labelled | Low | MEET.4.1 | PR.AA-05 | IAC-20 |
| GMT-005 | Meetings are recorded automatically | Low | MEET.5.1 | PR.DS-01 | DCH-01 |
| GMT-006 | Meetings are transcribed automatically | Low | MEET.5.2 | PR.DS-01 | DCH-01 |

### Workspace: Sites

| ID | Check | Severity | CISA SCuBA | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| GST-001 | Google Sites is enabled for users | Low | SITES.1.1 | PR.PS-01 | CFG-03 |

## Google Cloud (47 checks)

CIS numbers refer to the CIS Google Cloud Platform Foundation Benchmark (v3.0.0 numbering) and appear only where a check tests the same setting. Confirm them against the edition you hold; the benchmark is renumbered between releases.

### Cloud KMS

| ID | Check | Severity | CIS | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| KMS-001 | Cloud KMS keys are publicly accessible | Critical | 1.9 | PR.DS-01 | CRY-09 |
| KMS-002 | Cloud KMS keys not rotated within 90 days | Medium | 1.10 | PR.DS-01 | CRY-09 |

### Cloud SQL

| ID | Check | Severity | CIS | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| SQL-001 | Cloud SQL instances have public IP addresses | High | 6.6 | PR.IR-01 | NET-03 |
| SQL-002 | Cloud SQL authorized networks include 0.0.0.0/0 | High | 6.5 | PR.IR-01 | NET-04 |
| SQL-003 | Cloud SQL instances accept unencrypted connections | High | 6.4 | PR.DS-02 | CRY-03 |
| SQL-004 | Cloud SQL automated backups disabled | Medium | 6.7 | PR.DS-11 | BCD-11 |

### Cloud Storage

| ID | Check | Severity | CIS | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| STO-001 | Buckets are publicly accessible | Critical | 5.1 | PR.DS-01 | IAC-20 |
| STO-002 | Uniform bucket-level access disabled | Medium | 5.2 | PR.AA-05 | IAC-20 |

### Compute Engine

| ID | Check | Severity | CIS | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| CMP-001 | Instances use the default Compute Engine service account | Medium | 4.1 | PR.AA-05 | IAC-21 |
| CMP-002 | Default service account with full access to all Cloud APIs | High | 4.2 | PR.AA-05 | IAC-21 |
| CMP-003 | Instances accept project-wide SSH keys | Medium | 4.3 | PR.AA-05 | IAC-15 |
| CMP-004 | OS Login not enabled | Medium | 4.4 | PR.AA-01 | IAC-02 |
| CMP-005 | Serial port access enabled | Medium | 4.5 | PR.PS-01 | CFG-03 |
| CMP-006 | IP forwarding enabled on instances | Medium | 4.6 | PR.IR-01 | NET-01 |
| CMP-007 | Shielded VM vTPM or integrity monitoring off | Medium | 4.8 | PR.PS-01 | CFG-02 |
| CMP-008 | Instances have external IP addresses | Medium | 4.9 | PR.IR-01 | NET-03 |

### Identity and IAM

| ID | Check | Severity | CIS | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| IAM-001 | Owner or Editor role granted to users, groups or domains | High | - | PR.AA-05 | IAC-21 |
| IAM-002 | Service accounts with administrative privileges | High | 1.5 | PR.AA-05 | IAC-21 |
| IAM-003 | Project IAM policy grants roles to allUsers or allAuthenticatedUsers | Critical | - | PR.AA-05 | IAC-20 |
| IAM-004 | User-managed service account keys exist | High | 1.4 | PR.AA-01 | IAC-10 |
| IAM-005 | User-managed service account keys not rotated within 90 days | High | 1.7 | PR.AA-01 | IAC-10 |
| IAM-006 | Users hold Service Account User or Token Creator at project level | Medium | 1.6 | PR.AA-05 | IAC-21 |
| IAM-007 | Access granted to non-corporate accounts | Medium | 1.1 | PR.AA-01 | IAC-15 |
| IAM-008 | Default service accounts hold Editor or Owner | High | - | PR.AA-05 | IAC-21 |
| IAM-009 | Separation of duties: one principal is Service Account Admin and Service Account User | Medium | 1.8 | PR.AA-05 | HRS-11 |
| IAM-010 | API keys without restrictions | High | 1.13, 1.14 | PR.AA-01 | IAC-10 |
| IAM-011 | API keys older than 90 days | Low | 1.15 | PR.AA-01 | IAC-10 |

### Logging and monitoring

| ID | Check | Severity | CIS | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| LOG-001 | Cloud Audit Logs not fully enabled | High | 2.1 | PR.PS-04 | MON-03 |
| LOG-002 | No log sink exports all log entries | Medium | 2.2 | PR.PS-04 | MON-02 |
| LOG-003 | Log export bucket without a locked retention policy | Medium | 2.3 | PR.PS-04 | MON-10 |

### Networking

| ID | Check | Severity | CIS | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| NET-001 | Default network exists | Medium | 3.1 | PR.IR-01 | CFG-02 |
| NET-002 | Legacy network exists | Medium | 3.2 | PR.IR-01 | NET-01 |
| NET-003 | SSH (22) allowed from the internet | High | 3.6 | PR.IR-01 | NET-04 |
| NET-004 | RDP (3389) allowed from the internet | High | 3.7 | PR.IR-01 | NET-04 |
| NET-005 | All protocols or ports allowed from the internet | Critical | - | PR.IR-01 | NET-04 |
| NET-006 | VPC Flow Logs disabled on subnets | Medium | 3.8 | DE.CM-01 | MON-01 |
| NET-007 | DNSSEC disabled on public DNS zones | Medium | 3.3 | PR.IR-01 | NET-10 |
| NET-008 | DNSSEC uses RSASHA1 signing | Low | 3.4, 3.5 | PR.DS-02 | CRY-01 |

### Organization policy

| ID | Check | Severity | CIS | NIST CSF 2.0 | SCF |
|---|---|---|---|---|---|
| ORG-001 | Service account key creation is not blocked (iam.disableServiceAccountKeyCreation) | Medium | - | PR.PS-01 | CFG-02 |
| ORG-002 | Public access prevention not enforced (storage.publicAccessPrevention) | Medium | - | PR.PS-01 | CFG-02 |
| ORG-003 | OS Login not required (compute.requireOsLogin) | Medium | - | PR.PS-01 | CFG-02 |
| ORG-004 | External IPs on VMs not denied (compute.vmExternalIpAccess) | Medium | - | PR.PS-01 | CFG-02 |
| ORG-005 | Domain restricted sharing not set (iam.allowedPolicyMemberDomains) | Medium | - | PR.PS-01 | CFG-02 |
| ORG-006 | Public Cloud SQL IPs not restricted (sql.restrictPublicIp) | Medium | - | PR.PS-01 | CFG-02 |
| ORG-007 | Default network is still created for new projects (compute.skipDefaultNetworkCreation) | Low | - | PR.PS-01 | CFG-02 |
| ORG-008 | Serial port access not disabled (compute.disableSerialPortAccess) | Low | - | PR.PS-01 | CFG-02 |
| ORG-009 | Default service accounts get Editor automatically (iam.automaticIamGrantsForDefaultServiceAccounts) | Medium | - | PR.PS-01 | CFG-02 |

## CISA SCuBA coverage (105 of 138 policies)

Every Workspace baseline policy that is not covered, and why. The reasons: **manual** = no API exposes it; **audit-log** = visible only in the admin audit log; **unverified** = setting fields not verified; **not-adopted** = a deliberate choice; **not-applicable** = does not apply outside the original audience.

| Policy | Reason | Note |
|---|---|---|
| ASSUREDCONTROLS.1.1 | not-applicable | Applies only to tenants that use Assured Controls / Assured Workloads (a Google add-on); review manually if you do. |
| ASSUREDCONTROLS.1.2 | not-applicable | Applies only to tenants that use Assured Controls / Assured Workloads (a Google add-on); review manually if you do. |
| ASSUREDCONTROLS.2.1 | not-applicable | Applies only to tenants that use Assured Controls / Assured Workloads (a Google add-on); review manually if you do. |
| CALENDAR.3.2 | manual | How Calendar Interop authenticates to Microsoft 365 is not exposed by the APIs this tool reads. |
| CHAT.5.1 | audit-log | Chat content-reporting settings appear only in the admin audit log; reading the Reports API for them is planned. |
| CHAT.5.2 | audit-log | Chat content-reporting settings appear only in the admin audit log; reading the Reports API for them is planned. |
| COMMONCONTROLS.14.1 | manual | Log export to a SIEM and audit-log retention are not exposed by the read-only APIs. |
| COMMONCONTROLS.14.2 | manual | Log export to a SIEM and audit-log retention are not exposed by the read-only APIs. |
| COMMONCONTROLS.16.1 | unverified | The "additional Google services" are many per-service switches that are not mapped yet. |
| COMMONCONTROLS.16.2 | unverified | The "additional Google services" are many per-service switches that are not mapped yet. |
| COMMONCONTROLS.16.3 | unverified | The "additional Google services" are many per-service switches that are not mapped yet. |
| COMMONCONTROLS.16.4 | unverified | The "additional Google services" are many per-service switches that are not mapped yet. |
| COMMONCONTROLS.2.1 | manual | Context-aware access levels are managed in Access Context Manager, which this tool does not read. |
| COMMONCONTROLS.3.1 | audit-log | Post-SSO verification appears only in the admin audit log; reading the Reports API for it is planned. |
| COMMONCONTROLS.3.2 | audit-log | Post-SSO verification appears only in the admin audit log; reading the Reports API for it is planned. |
| COMMONCONTROLS.8.3 | unverified | The recovery-contact setting is not in the settings list we could verify the field names for. |
| COMMONCONTROLS.9.1 | manual | Advanced Protection Program enrolment is not exposed by the APIs this tool reads. |
| COMMONCONTROLS.9.2 | manual | Advanced Protection Program enrolment is not exposed by the APIs this tool reads. |
| DRIVEDOCS.1.10 | manual | Form-response behaviour has no API. |
| DRIVEDOCS.1.11 | manual | Form-response behaviour has no API. |
| DRIVEDOCS.2.2 | not-adopted | CISA wants people who are not members of a shared drive to be allowed on its files. That is a policy choice we leave to the organisation (GDR-011 reports shared drives open to outsiders). |
| DRIVEDOCS.5.2 | manual | Ransomware-corruption monitoring is an alert setting with no API. |
| GEMINI.1.1 | unverified | The Gemini setting fields cannot be verified without a tenant that has Gemini, and CISA reads most of them from audit logs. |
| GEMINI.2.1 | unverified | The Gemini setting fields cannot be verified without a tenant that has Gemini, and CISA reads most of them from audit logs. |
| GEMINI.3.1 | unverified | The Gemini setting fields cannot be verified without a tenant that has Gemini, and CISA reads most of them from audit logs. |
| GEMINI.3.2 | unverified | The Gemini setting fields cannot be verified without a tenant that has Gemini, and CISA reads most of them from audit logs. |
| GEMINI.4.1 | unverified | The Gemini setting fields cannot be verified without a tenant that has Gemini, and CISA reads most of them from audit logs. |
| GMAIL.13.1 | audit-log | The external-recipient warning appears only in the admin audit log. |
| GMAIL.16.1 | audit-log | The security sandbox appears only in the admin audit log. |
| GMAIL.4.3 | not-applicable | Requires sending DMARC reports to a US federal address. GML-006 checks that you collect DMARC reports at all. |
| MEET.6.1 | audit-log | The AI-notes settings appear only in the admin audit log. |
| MEET.6.2 | audit-log | The AI-notes settings appear only in the admin audit log. |
| MEET.6.3 | audit-log | The AI-notes settings appear only in the admin audit log. |

## Not covered yet

- Google Cloud: IAM policies, audit configuration and log sinks set on a folder or the organisation are not visible from a project.
- Google Cloud: BigQuery dataset access, GKE cluster hardening, Cloud Functions / Cloud Run exposure, VPC Service Controls, Security Command Center findings, and the CIS log-metric alert recommendations (2.4 to 2.11).
- Google Cloud: Cloud KMS is scanned only in the locations passed with `--kms-location` (default `global`).
