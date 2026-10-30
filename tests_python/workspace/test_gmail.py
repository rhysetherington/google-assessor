"""Workspace Gmail and email security (GML-001..GML-034) against the fake tenant: console settings and DNS records."""

import unittest

from google_gap_assessment.workspace.checks import gmail as MODULE
from google_gap_assessment.workspace.context import WsOptions
from tests_python.workspace.helpers import healthy_passes, run, run_cases
from tests_python.workspace.ws_fakes import Err

D = "contoso.com"
ATT, LNK, SPF_ = "gmail.email_attachment_safety", "gmail.links_and_external_images", "gmail.spoofing_and_authentication"
KEY = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestkeytestkeytestkeytestkey"


def setting(name, **fields):
    return lambda t: t.settings.__setitem__(name, {**t.settings.get(name, {}), **fields})


def drop(name):
    return lambda t: t.settings.pop(name)


def dns(records):
    """Replace DNS records. Keys are the name in front of the domain ("_dmarc", "google._domainkey"); "" is the domain itself; None removes."""
    def mutate(t):
        for prefix, value in records.items():
            name = f"{prefix}.{D}" if prefix else D
            if value is None:
                t.dns.pop(name, None)
            else:
                t.dns[name] = value
    return mutate


def sub_domain(name="mail.contoso.com", records=None):
    """Add a secondary domain that publishes the given records (full DNS names) and nothing else."""
    def mutate(t):
        t.domains.append({"domainName": name, "isPrimary": False, "verified": True, "domainAliases": []})
        t.dns.update(records or {})
    return mutate


def no_dns(t):
    pass


# (name, finding id, expected status, mutate(tenant), options, text that must appear in affected/detail)
CASES = [
    # --- console settings ---
    ("GML-001 gap: delegation allowed", "GML-001", "Gap", setting("gmail.mail_delegation", enableMailDelegation=True), None, "enableMailDelegation"),
    ("GML-001 pass: Google's default is off, so no policy means pass", "GML-001", "Pass", drop("gmail.mail_delegation"), None, None),
    ("GML-001 gap: an OU re-enables delegation", "GML-001", "Gap", lambda t: t.override("/Sales", "gmail.mail_delegation", {"enableMailDelegation": True}), None, "/Sales"),
    ("GML-010 gap: encrypted attachment protection off", "GML-010", "Gap", setting(ATT, enableEncryptedAttachmentProtection=False), None, None),
    ("GML-011 gap: scripts protection off", "GML-011", "Gap", setting(ATT, enableAttachmentWithScriptsProtection=False), None, None),
    ("GML-012 gap: anomalous type protection off", "GML-012", "Gap", setting(ATT, enableAnomalousAttachmentProtection=False), None, None),
    ("GML-013 gap: future attachment settings not applied", "GML-013", "Gap", setting(ATT, applyFutureRecommendedSettingsAutomatically=False), None, None),
    ("GML-014 gap: attachment warning only", "GML-014", "Gap", setting(ATT, encryptedAttachmentProtectionConsequence="SHOW_WARNING"), None, "SHOW_WARNING"),
    ("GML-014 NotAssessed: no consequence fields returned", "GML-014", "NotAssessed",
     lambda t: t.settings.__setitem__(ATT, {"enableEncryptedAttachmentProtection": True}), None, None),
    ("GML-015 gap: shortener scanning off", "GML-015", "Gap", setting(LNK, enableShortenerScanning=False), None, None),
    ("GML-016 gap: image scanning off", "GML-016", "Gap", setting(LNK, enableExternalImageScanning=False), None, None),
    ("GML-017 gap: aggressive warnings off", "GML-017", "Gap", setting(LNK, enableAggressiveWarningsOnUntrustedLinks=False), None, None),
    ("GML-018 gap: future link settings not applied", "GML-018", "Gap", setting(LNK, applyFutureSettingsAutomatically=False), None, None),
    ("GML-019 gap: domain-name spoofing protection off", "GML-019", "Gap", setting(SPF_, detectDomainNameSpoofing=False), None, None),
    ("GML-020 gap: employee-name spoofing protection off", "GML-020", "Gap", setting(SPF_, detectEmployeeNameSpoofing=False), None, None),
    ("GML-021 gap: domain spoofing from unauthenticated senders", "GML-021", "Gap", setting(SPF_, detectDomainSpoofingFromUnauthenticatedSenders=False), None, None),
    ("GML-022 gap: unauthenticated email not flagged", "GML-022", "Gap", setting(SPF_, detectUnauthenticatedEmails=False), None, None),
    ("GML-023 gap: spoofed email stays in the inbox", "GML-023", "Gap", setting(SPF_, domainSpoofingConsequence="KEEP_IN_INBOX"), None, "KEEP_IN_INBOX"),
    ("GML-024 gap: future spoofing settings not applied", "GML-024", "Gap", setting(SPF_, applyFutureSettingsAutomatically=False), None, None),
    ("GML-025 gap: email import allowed", "GML-025", "Gap", setting("gmail.user_email_uploads", enableMailAndContactsImport=True), None, None),
    ("GML-026 gap: POP enabled", "GML-026", "Gap", setting("gmail.pop_access", enablePopAccess=True), None, "POP=True"),
    ("GML-026 gap: IMAP enabled", "GML-026", "Gap", setting("gmail.imap_access", enableImapAccess=True), None, "IMAP=True"),
    ("GML-027 gap: Sync for Outlook on", "GML-027", "Gap", setting("gmail.workspace_sync_for_outlook", enableGoogleWorkspaceSyncForMicrosoftOutlook=True), None, None),
    ("GML-028 gap: auto-forwarding allowed", "GML-028", "Gap", setting("gmail.auto_forwarding", enableAutoForwarding=True), None, None),
    ("GML-028 gap: forwarding allowed for one OU only", "GML-028", "Gap", lambda t: t.override("/Sales", "gmail.auto_forwarding", {"enableAutoForwarding": True}), None, "/Sales"),
    ("GML-029 gap: per-user outbound gateway", "GML-029", "Gap", setting("gmail.per_user_outbound_gateway", allowUsersToUseExternalSmtpServers=True), None, None),
    ("GML-029 pass: never changed, Google documents the default as off", "GML-029", "Pass", lambda t: t.settings.pop("gmail.per_user_outbound_gateway"), None, None),
    ("GML-030 gap: allowlisted IPs", "GML-030", "Gap", setting("gmail.email_spam_filter_ip_allowlist", allowedIpAddresses=["203.0.113.0/24"]), None, "1 allowlisted"),
    ("GML-031 gap: pre-delivery scanning off", "GML-031", "Gap", setting("gmail.enhanced_pre_delivery_message_scanning", enableImprovedSuspiciousContentDetection=False), None, None),
    ("GML-032 gap: no storage rule configured", "GML-032", "Gap", lambda t: (t.settings.pop("gmail.comprehensive_mail_storage"), t.settings.pop("gmail.rule_states")), None, "no comprehensive"),
    ("GML-032 gap: the rule is disabled", "GML-032", "Gap", lambda t: t.settings.__setitem__("gmail.rule_states", {"ruleStates": [{"ruleId": "rule-1", "enabled": False}]}), None, "disabled"),
    ("GML-033 gap: a spam override rule exists", "GML-033", "Gap", setting("gmail.spam_override_lists", spamOverride=[{"description": "Partner allowlist", "hideWarningBannerForAll": False}]), None, "Partner allowlist"),
    ("GML-034 gap: warning banners hidden for all", "GML-034", "Gap", setting("gmail.spam_override_lists", spamOverride=[{"description": "VIP", "hideWarningBannerForAll": True}]), None, "VIP"),
    ("GML-034 pass: an override that keeps banners", "GML-034", "Pass", setting("gmail.spam_override_lists", spamOverride=[{"description": "Partner", "hideWarningBannerForAll": False}]), None, None),
    # --- Gmail switched off ---
    ("GML-028 pass (not applicable): Gmail is off for the tenant", "GML-028", "Pass", (lambda t: (t.settings.__setitem__("gmail.service_status", {"serviceState": "DISABLED"}),
                                                                                                       t.settings.__setitem__("gmail.auto_forwarding", {"enableAutoForwarding": True}))), None, "switched off"),
    ("GML-028 pass: an OU with Gmail off is skipped", "GML-028", "Pass",
     lambda t: (t.override("/Sales", "gmail.service_status", {"serviceState": "DISABLED"}), t.override("/Sales", "gmail.auto_forwarding", {"enableAutoForwarding": True})), None, None),
    ("GML-032 pass (not applicable): Gmail is off", "GML-032", "Pass", lambda t: t.settings.__setitem__("gmail.service_status", {"serviceState": "DISABLED"}), None, "switched off"),
    # --- DKIM ---
    ("GML-002 gap: no DKIM key", "GML-002", "Gap", dns({"google._domainkey": None}), None, "contoso.com"),
    ("GML-002 pass: Google's receive-only test alias domain is not checked", "GML-002", "Pass", sub_domain("contoso.com.test-google-a.com"), None, None),
    ("GML-003 pass: the test alias domain has no SPF and that is fine", "GML-003", "Pass", sub_domain("contoso.com.test-google-a.com"), None, None),
    ("GML-002 gap: revoked key (empty p=)", "GML-002", "Gap", dns({"google._domainkey": ["v=DKIM1; k=rsa; p="]}), None, None),
    ("GML-002 gap: a secondary domain has no key", "GML-002", "Gap", sub_domain("mail.contoso.com"), None, "mail.contoso.com"),
    ("GML-002 NotAssessed: DNS switched off", "GML-002", "NotAssessed", no_dns, WsOptions(check_dns=False), "--no-dns"),
    ("GML-002 NotAssessed: the lookup failed", "GML-002", "NotAssessed", lambda t: t.dns.__setitem__(f"google._domainkey.{D}", Err("Transient", "timeout")), None, "failed"),
    # --- SPF ---
    ("GML-003 gap: no SPF record", "GML-003", "Gap", dns({"": ["google-site-verification=abc"]}), None, "no SPF"),
    ("GML-003 gap: soft fail", "GML-003", "Gap", dns({"": ["v=spf1 include:_spf.google.com ~all"]}), None, "~all"),
    ("GML-003 gap: neutral", "GML-003", "Gap", dns({"": ["v=spf1 include:_spf.google.com ?all"]}), None, "?all"),
    ("GML-003 gap: anyone may send (+all)", "GML-003", "Gap", dns({"": ["v=spf1 +all"]}), None, "+all"),
    ("GML-003 gap: two SPF records", "GML-003", "Gap", dns({"": ["v=spf1 -all", "v=spf1 include:x.example -all"]}), None, "more than one"),
    ("GML-003 gap: no all mechanism", "GML-003", "Gap", dns({"": ["v=spf1 include:_spf.google.com"]}), None, "no 'all'"),
    ("GML-003 pass: redirect to a hard-fail record", "GML-003", "Pass", lambda t: (t.dns.__setitem__(D, ["v=spf1 redirect=_spf.contoso.net"]), t.dns.__setitem__("_spf.contoso.net", ["v=spf1 ip4:203.0.113.0/24 -all"])), None, None),
    ("GML-003 gap: redirect to a soft-fail record", "GML-003", "Gap", lambda t: (t.dns.__setitem__(D, ["v=spf1 redirect=_spf.contoso.net"]), t.dns.__setitem__("_spf.contoso.net", ["v=spf1 ~all"])), None, "~all"),
    # --- DMARC ---
    ("GML-004 gap: no DMARC record", "GML-004", "Gap", dns({"_dmarc": None}), None, "no DMARC"),
    ("GML-004 gap: two DMARC records", "GML-004", "Gap", dns({"_dmarc": ["v=DMARC1; p=reject", "v=DMARC1; p=none"]}), None, "more than one"),
    ("GML-004 pass: a subdomain inherits its parent's record", "GML-004", "Pass", sub_domain("mail.contoso.com"), None, None),
    ("GML-005 gap: p=none", "GML-005", "Gap", dns({"_dmarc": ["v=DMARC1; p=none; rua=mailto:a@contoso.com"]}), None, "'none'"),
    ("GML-005 gap: p=quarantine", "GML-005", "Gap", dns({"_dmarc": ["v=DMARC1; p=quarantine; rua=mailto:a@contoso.com"]}), None, "quarantine"),
    ("GML-005 gap: subdomain inherits a parent whose sp is none", "GML-005", "Gap", lambda t: (sub_domain("mail.contoso.com")(t), t.dns.__setitem__(f"_dmarc.{D}", ["v=DMARC1; p=reject; sp=none; rua=mailto:a@contoso.com"])), None, "mail.contoso.com"),
    ("GML-005 pass: subdomain inherits p=reject with no sp", "GML-005", "Pass", lambda t: (sub_domain("mail.contoso.com")(t), t.dns.__setitem__(f"_dmarc.{D}", ["v=DMARC1; p=reject; rua=mailto:a@contoso.com"])), None, None),
    ("GML-006 gap: no reporting address", "GML-006", "Gap", dns({"_dmarc": ["v=DMARC1; p=reject"]}), None, "rua"),
    ("GML-007 gap: pct below 100", "GML-007", "Gap", dns({"_dmarc": ["v=DMARC1; p=reject; pct=50; rua=mailto:a@contoso.com"]}), None, "50%"),
    ("GML-007 pass: pct=100", "GML-007", "Pass", dns({"_dmarc": ["v=DMARC1; p=reject; pct=100; rua=mailto:a@contoso.com"]}), None, None),
    ("GML-008 gap: no MTA-STS", "GML-008", "Gap", dns({"_mta-sts": None}), None, "MTA-STS"),
    ("GML-009 gap: no TLS-RPT", "GML-009", "Gap", dns({"_smtp._tls": None}), None, "TLS-RPT"),
]


class GmailChecks(unittest.TestCase):
    def test_healthy_tenant_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)

    def test_every_gmail_check_has_a_case_for_a_gap(self):
        covered = {c[1] for c in CASES if c[2] == "Gap"}
        self.assertEqual({chk.id for chk in MODULE.CHECKS}, covered)

    def test_dns_is_never_queried_when_switched_off(self):
        findings, ctx = run(MODULE, None, WsOptions(check_dns=False))
        self.assertEqual([], ctx.resolver.lookups)
        self.assertEqual({"NotAssessed"}, {f["Status"] for f in findings if f["FindingId"] in ("GML-002", "GML-003", "GML-004", "GML-008")})

    def test_every_domain_is_looked_up_once_per_record_type(self):
        _, ctx = run(MODULE, sub_domain("mail.contoso.com", {"mail.contoso.com": ["v=spf1 -all"]}))
        self.assertIn("_dmarc.mail.contoso.com", ctx.resolver.lookups)
        self.assertIn("google._domainkey.mail.contoso.com", ctx.resolver.lookups)


if __name__ == "__main__":
    unittest.main()
