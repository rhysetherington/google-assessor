"""Workspace Gmail and email security (GML-xxx): mail delegation and forwarding, attachment and link protection, spoofing protection,
mail client access, spam-filter bypasses, and the DNS records that authenticate your mail (DKIM, SPF, DMARC, MTA-STS, TLS-RPT).

Console settings come from the Policy API. DNS records are read over DNS-over-HTTPS for every domain in the tenant; with --no-dns those
checks are reported as not assessed. A product switched off for the tenant (Gmail disabled) makes the console checks not applicable.
"""

from __future__ import annotations

from ...model import ProjectResult, gap_or_pass
from .. import mail_dns
from ..context import WsContext
from .common import PolicyRule, describe_fields, dns_check, flag, is_in, policy_result, policy_result_many, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Workspace: Gmail and email security"   # the name the control mapping and reports use for this domain

SVC = "gmail.service_status"
ATTACH = "gmail.email_attachment_safety"
LINKS = "gmail.links_and_external_images"
SPOOF = "gmail.spoofing_and_authentication"
REMOVED_FROM_INBOX = ("SPAM_FOLDER", "QUARANTINE")


def _consequences_ok(*keys: str):
    """Every consequence the API returned is 'move to spam' or 'quarantine'; None when it returned none (so it cannot be judged)."""
    def ok(s):
        present = [s[k] for k in keys if s.get(k) is not None]
        return None if not present else all(v in REMOVED_FROM_INBOX for v in present)
    return ok


def _gmail_rule(id_, setting, ok, fields, detail, question):
    return PolicyRule(id_, setting, ok, describe_fields(*fields), detail, question, service=SVC)


RULES = [
    _gmail_rule("GML-001", "gmail.mail_delegation", flag("enableMailDelegation", False), ["enableMailDelegation"],
                "Delegation lets one account read and send as another; if it is needed, restrict it and review who holds it.",
                "Users cannot delegate access to their mailbox"),
    _gmail_rule("GML-010", ATTACH, flag("enableEncryptedAttachmentProtection", True), ["enableEncryptedAttachmentProtection"],
                "Password-protected attachments hide malware from scanners; protection keeps them away from inboxes.",
                "Protection against encrypted attachments from untrusted senders is on"),
    _gmail_rule("GML-011", ATTACH, flag("enableAttachmentWithScriptsProtection", True), ["enableAttachmentWithScriptsProtection"],
                "Attachments that contain scripts are a common malware route.", "Protection against attachments with scripts from untrusted senders is on"),
    _gmail_rule("GML-012", ATTACH, flag("enableAnomalousAttachmentProtection", True), ["enableAnomalousAttachmentProtection"],
                "Files whose type does not match their extension are a classic way to slip malware past users.", "Protection against anomalous attachment types is on"),
    _gmail_rule("GML-013", ATTACH, flag("applyFutureRecommendedSettingsAutomatically", True), ["applyFutureRecommendedSettingsAutomatically"],
                "New attachment protections Google adds should reach the tenant without anyone having to remember to switch them on.",
                "Google's future recommended attachment settings are applied automatically"),
    _gmail_rule("GML-014", ATTACH, _consequences_ok("anomalousAttachmentProtectionConsequence", "encryptedAttachmentProtectionConsequence",
                                                    "attachmentWithScriptsProtectionConsequence"),
                ["anomalousAttachmentProtectionConsequence", "encryptedAttachmentProtectionConsequence", "attachmentWithScriptsProtectionConsequence"],
                "A warning banner leaves the dangerous message in the inbox for a user to open; spam or quarantine keeps it out.",
                "Suspicious attachments are moved to spam or quarantine, not left in the inbox"),
    _gmail_rule("GML-015", LINKS, flag("enableShortenerScanning", True), ["enableShortenerScanning"],
                "Link shorteners hide the real destination; scanning follows them.", "Links behind shorteners are scanned"),
    _gmail_rule("GML-016", LINKS, flag("enableExternalImageScanning", True), ["enableExternalImageScanning"],
                "Images in email can carry tracking or exploits; scanning checks them.", "Images from external senders are scanned"),
    _gmail_rule("GML-017", LINKS, flag("enableAggressiveWarningsOnUntrustedLinks", True), ["enableAggressiveWarningsOnUntrustedLinks"],
                "Stronger warnings on untrusted links make users think before clicking.", "Aggressive warnings on untrusted links are on"),
    _gmail_rule("GML-018", LINKS, flag("applyFutureSettingsAutomatically", True), ["applyFutureSettingsAutomatically"],
                "New link and image protections should apply without manual action.", "Future link and image protection settings are applied automatically"),
    _gmail_rule("GML-019", SPOOF, flag("detectDomainNameSpoofing", True), ["detectDomainNameSpoofing"],
                "Look-alike domains (contoso-corp.com for contoso.com) are the backbone of business email compromise.", "Protection against domain-name spoofing is on"),
    _gmail_rule("GML-020", SPOOF, flag("detectEmployeeNameSpoofing", True), ["detectEmployeeNameSpoofing"],
                "Attackers send mail displaying an employee's name from an outside address.", "Protection against employee-name spoofing is on"),
    _gmail_rule("GML-021", SPOOF, flag("detectDomainSpoofingFromUnauthenticatedSenders", True), ["detectDomainSpoofingFromUnauthenticatedSenders"],
                "Mail that claims to be from your domain but fails authentication should be treated as spoofed.",
                "Protection against your domain being spoofed by unauthenticated senders is on"),
    _gmail_rule("GML-022", SPOOF, flag("detectUnauthenticatedEmails", True), ["detectUnauthenticatedEmails"],
                "Unauthenticated mail is more likely to be forged; users should be told.", "Unauthenticated email is flagged"),
    _gmail_rule("GML-023", SPOOF, _consequences_ok("domainSpoofingConsequence", "domainNameSpoofingConsequence", "employeeNameSpoofingConsequence",
                                                   "groupsSpoofingConsequence", "unauthenticatedEmailConsequence"),
                ["domainSpoofingConsequence", "domainNameSpoofingConsequence", "employeeNameSpoofingConsequence", "groupsSpoofingConsequence",
                 "unauthenticatedEmailConsequence"],
                "Spoofed mail left in the inbox with only a warning still gets read and clicked; spam or quarantine keeps it away.",
                "Spoofed or unauthenticated email is moved to spam or quarantine, not left in the inbox"),
    _gmail_rule("GML-024", SPOOF, flag("applyFutureSettingsAutomatically", True), ["applyFutureSettingsAutomatically"],
                "New anti-spoofing protections should apply without manual action.", "Future spoofing and authentication settings are applied automatically"),
    _gmail_rule("GML-025", "gmail.user_email_uploads", flag("enableMailAndContactsImport", False), ["enableMailAndContactsImport"],
                "Importing mail from outside brings content that bypasses the usual inbound scanning.", "Users cannot import email from other providers"),
    _gmail_rule("GML-027", "gmail.workspace_sync_for_outlook", flag("enableGoogleWorkspaceSyncForMicrosoftOutlook", False), ["enableGoogleWorkspaceSyncForMicrosoftOutlook"],
                "Another sync path into mailboxes that has to be secured and monitored; turn it off unless Outlook is genuinely in use.",
                "Google Workspace Sync for Microsoft Outlook is off"),
    _gmail_rule("GML-028", "gmail.auto_forwarding", flag("enableAutoForwarding", False), ["enableAutoForwarding"],
                "Automatic forwarding to outside addresses is a standard way to exfiltrate mail after an account takeover.", "Users cannot automatically forward email outside the organisation"),
    _gmail_rule("GML-029", "gmail.per_user_outbound_gateway", flag("allowUsersToUseExternalSmtpServers", False), ["allowUsersToUseExternalSmtpServers"],
                "Per-user outbound gateways let a user send company mail through a server you do not control.", "Users cannot send mail through their own external SMTP servers"),
    _gmail_rule("GML-031", "gmail.enhanced_pre_delivery_message_scanning", flag("enableImprovedSuspiciousContentDetection", True), ["enableImprovedSuspiciousContentDetection"],
                "Scanning messages for suspicious content before delivery catches more phishing than scanning after.", "Enhanced pre-delivery message scanning is on"),
]
CHECKS.extend(r.as_check() for r in RULES)


@check("GML-026")
def pop_and_imap_off(ctx: WsContext, tenant: str):
    """POP and IMAP access are both off (they bypass modern authentication and its protections)."""
    return policy_result_many(ctx, tenant, "GML-026", ["gmail.pop_access", "gmail.imap_access"],
                              lambda v: None if None in (v["gmail.pop_access"].get("enablePopAccess"), v["gmail.imap_access"].get("enableImapAccess"))
                              else not (v["gmail.pop_access"]["enablePopAccess"] or v["gmail.imap_access"]["enableImapAccess"]),
                              lambda v: f"POP={v['gmail.pop_access'].get('enablePopAccess')}, IMAP={v['gmail.imap_access'].get('enableImapAccess')}",
                              "Legacy mail protocols authenticate with a password alone and are hard to monitor or restrict.", service=SVC)


@check("GML-030")
def spam_filter_ip_allowlist_empty(ctx: WsContext, tenant: str):
    """The Gmail spam-filter IP allowlist is empty (mail from listed IPs skips spam filtering)."""
    return policy_result(ctx, tenant, "GML-030", "gmail.email_spam_filter_ip_allowlist",
                         lambda s: None if s.get("allowedIpAddresses") is None else len(s["allowedIpAddresses"]) == 0,
                         lambda s: f"{len(s.get('allowedIpAddresses') or [])} allowlisted IP range(s)",
                         "Allowlisted addresses bypass spam filtering, so a compromised or spoofed host on the list delivers straight to inboxes.", SVC)


@check("GML-032")
def comprehensive_mail_storage(ctx: WsContext, tenant: str):
    """A comprehensive mail storage rule exists and is switched on (a copy of all mail, including outbound, is kept)."""
    ps = ctx.policies()
    storage = ps.top("gmail.comprehensive_mail_storage")
    if (ps.top(SVC) or {}).get("serviceState") == "DISABLED":
        return [ProjectResult(tenant, "GML-032", "NotApplicable", [], "Gmail is switched off for the tenant.")]
    if not storage or not storage.get("ruleId"):
        return [gap_or_pass(tenant, "GML-032", [f"{tenant}: no comprehensive mail storage rule is configured"],
                            "Without it, mail a user deletes is gone from your control, which hampers investigations and retention duties.")]
    states = (ps.top("gmail.rule_states") or {}).get("ruleStates") or []
    enabled = any(r.get("ruleId") == storage["ruleId"] and r.get("enabled") for r in states)
    return [gap_or_pass(tenant, "GML-032", [] if enabled else [f"{tenant}: the comprehensive mail storage rule exists but is disabled"],
                        "Without it, mail a user deletes is gone from your control, which hampers investigations and retention duties.")]


def _spam_overrides(ctx: WsContext, tenant: str, finding_id: str, picks, detail: str):
    ps = ctx.policies()
    if (ps.top(SVC) or {}).get("serviceState") == "DISABLED":
        return [ProjectResult(tenant, finding_id, "NotApplicable", [], "Gmail is switched off for the tenant.")]
    hits = []
    for scope, value in [("/", ps.top("gmail.spam_override_lists") or {})] + ps.overrides("gmail.spam_override_lists"):
        for entry in value.get("spamOverride") or []:
            if picks(entry):
                hits.append(f"{tenant}: {scope} - spam-filter override '{entry.get('description') or 'unnamed'}'")
    return [gap_or_pass(tenant, finding_id, hits, detail)]


@check("GML-033")
def spam_filter_overrides(ctx: WsContext, tenant: str):
    """No rule makes Gmail skip spam filtering for chosen senders (an allowlist rule)."""
    return _spam_overrides(ctx, tenant, "GML-033", lambda e: True,
                           "Senders on a spam-override list skip filtering, so one compromised partner or spoofed domain on it reaches inboxes unchecked. Review each.")


@check("GML-034")
def warning_banners_hidden_for_all(ctx: WsContext, tenant: str):
    """No spam-override rule hides warning banners for all senders."""
    return _spam_overrides(ctx, tenant, "GML-034", lambda e: bool(e.get("hideWarningBannerForAll")),
                           "Hiding warning banners for everyone on a list removes the signal users rely on to spot suspicious mail.")


# --- DNS: DKIM, SPF, DMARC, MTA-STS, TLS-RPT (per domain) ----------------------------------------------------------------------

@check("GML-002")
def dkim_published(ctx: WsContext, tenant: str):
    """DKIM is set up: the 'google' selector publishes a valid public key for every domain (custom selectors are not detected)."""
    def per_domain(domain, resolver):
        return None if mail_dns.has_valid_dkim_key(resolver.txt(f"{mail_dns.GOOGLE_DKIM_SELECTOR}._domainkey.{domain}")) \
            else f"no DKIM key at {mail_dns.GOOGLE_DKIM_SELECTOR}._domainkey (a custom selector would not be seen)"
    return dns_check(ctx, tenant, "GML-002", per_domain, "DKIM signs outgoing mail so receivers can tell it really came from you; without it DMARC cannot be relied on.")


@check("GML-003")
def spf_hard_fail(ctx: WsContext, tenant: str):
    """Every domain publishes exactly one SPF record that ends in -all (or redirects to one that does)."""
    messages = {"none": "no SPF record", "multiple": "more than one SPF record (invalid)", "no-all": "SPF record has no 'all' mechanism",
                "softfail": "SPF ends in ~all (soft fail), not -all", "neutral": "SPF ends in ?all (neutral)", "open": "SPF ends in +all (anyone may send)"}
    def per_domain(domain, resolver):
        verdict = mail_dns.spf_verdict(resolver, domain)
        return None if verdict == "hardfail" else messages[verdict]
    return dns_check(ctx, tenant, "GML-003", per_domain, "SPF lists who may send for the domain; a hard fail tells receivers to reject everyone else.")


def _dmarc(ctx, tenant, finding_id, judge_tags, detail):
    def per_domain(domain, resolver):
        records, where = mail_dns.find_dmarc(resolver, domain)
        if not records:
            return "no DMARC record (neither on the domain nor its parent)"
        if len(records) > 1:
            return "more than one DMARC record (invalid)"
        tags = mail_dns.dmarc_record(records) or {}
        return judge_tags(tags, where == domain)
    return dns_check(ctx, tenant, finding_id, per_domain, detail)


@check("GML-004")
def dmarc_published(ctx: WsContext, tenant: str):
    """Every domain has exactly one DMARC record (its own, or its parent domain's)."""
    return _dmarc(ctx, tenant, "GML-004", lambda tags, own: None,
                  "DMARC tells receivers what to do with mail that fails SPF and DKIM; without it spoofing your domain is easy.")


@check("GML-005")
def dmarc_reject(ctx: WsContext, tenant: str):
    """DMARC policy is reject (for a subdomain using its parent's record: sp=reject, or p=reject with no sp)."""
    def judge(tags, own):
        policy = tags.get("p", "").lower() if own else (tags.get("sp") or tags.get("p") or "").lower()
        return None if policy == "reject" else f"DMARC policy is '{policy or 'missing'}', not reject"
    return _dmarc(ctx, tenant, "GML-005", judge, "Only a reject policy actually stops spoofed mail; none and quarantine merely report or hide it.")


@check("GML-006")
def dmarc_reporting(ctx: WsContext, tenant: str):
    """DMARC aggregate reports (rua) are collected, so spoofing attempts and legitimate senders can be seen."""
    return _dmarc(ctx, tenant, "GML-006", lambda tags, own: None if tags.get("rua") else "DMARC record has no rua= reporting address",
                  "Without aggregate reports you cannot tell who is sending as you, or whether tightening the policy would break real mail.")


@check("GML-007")
def dmarc_applies_to_all_mail(ctx: WsContext, tenant: str):
    """The DMARC record applies to all mail (pct is 100 or absent)."""
    def judge(tags, own):
        pct = tags.get("pct")
        return None if pct is None or pct.strip() == "100" else f"DMARC applies to only {pct}% of mail"
    return _dmarc(ctx, tenant, "GML-007", judge, "A pct below 100 leaves the rest of the mail unprotected.")


@check("GML-008")
def mta_sts_published(ctx: WsContext, tenant: str):
    """Every domain publishes an MTA-STS record (_mta-sts TXT), asking senders to use authenticated TLS to deliver."""
    return dns_check(ctx, tenant, "GML-008",
                     lambda d, r: None if any(rec.lower().startswith("v=stsv1") for rec in r.txt(f"_mta-sts.{d}")) else "no MTA-STS record",
                     "MTA-STS stops attackers downgrading inbound mail to unencrypted delivery. (Only the DNS record is checked, not the policy file.)")


@check("GML-009")
def tls_reporting_published(ctx: WsContext, tenant: str):
    """Every domain publishes a TLS reporting record (_smtp._tls TXT), so delivery failures and downgrade attempts are reported."""
    return dns_check(ctx, tenant, "GML-009",
                     lambda d, r: None if any(rec.lower().startswith("v=tlsrptv1") for rec in r.txt(f"_smtp._tls.{d}")) else "no TLS-RPT record",
                     "TLS reports tell you when senders cannot deliver securely to you.")


def collect(ctx: WsContext, tenants: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, tenants, CHECKS, only)
