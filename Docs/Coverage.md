# Coverage

Generated from `google_gap_assessment/data/control_mapping.json` by `python3 -m google_gap_assessment.coverage`; do not edit by hand. 78 checks.

## Google Workspace (31 checks)

SCuBA references are the CISA Secure Cloud Business Applications baseline policies each check covers (`COMMONCONTROLS.5.2` is `GWS.COMMONCONTROLS.5.2v1`); a check with `-` is an addition of our own.

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

## Not covered yet

- Google Cloud: IAM policies, audit configuration and log sinks set on a folder or the organisation are not visible from a project.
- Google Cloud: BigQuery dataset access, GKE cluster hardening, Cloud Functions / Cloud Run exposure, VPC Service Controls, Security Command Center findings, and the CIS log-metric alert recommendations (2.4 to 2.11).
- Google Cloud: Cloud KMS is scanned only in the locations passed with `--kms-location` (default `global`).
