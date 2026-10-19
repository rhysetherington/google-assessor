"""A fake gcloud for the offline suite: fixtures describe a healthy project, each test breaks one thing.

``FakeGcloud`` is a real ``Gcloud`` whose ``run`` serves fixtures, so caching, list/one normalisation and the
read-only gate are the production code. No gcloud binary, account or network is involved.

Fixture keys are the command, plus the arguments when they matter: 'compute instances list',
'iam service-accounts keys list --iam-account=a@b --managed-by=user'. Prefix a key with '<project>::' to serve one project only.
An ``Err`` value makes the call fail the way gcloud does.
"""

from __future__ import annotations

import copy

from gcp_gap_assessment.gcloud import Gcloud, GcloudError, is_read_only

PROJECT = "test-project-one"
SA = f"app@{PROJECT}.iam.gserviceaccount.com"
DEFAULT_COMPUTE_SA = "123456789012-compute@developer.gserviceaccount.com"
KEYS_KEY = f"iam service-accounts keys list --iam-account={SA} --managed-by=user"
DENIED = None  # set below


class Err:
    def __init__(self, category: str, message: str = "error"):
        self.category, self.message = category, message


DENIED = Err("PermissionDenied", "PERMISSION_DENIED: caller does not have permission")
DISABLED = Err("ApiDisabled", "SERVICE_DISABLED: API has not been used in project")


class FakeGcloud(Gcloud):
    def __init__(self, fixtures: dict, impersonate=None):
        super().__init__(path="/fake/gcloud", impersonate=impersonate, runner=lambda a: (1, "", "runner must not be used"))
        self.fixtures = fixtures
        self.calls: "list[str]" = []

    def run(self, command, arguments=(), project=None, max_retries=4, impersonate=True):
        if not is_read_only(command.split()):
            raise AssertionError(f"NOT READ-ONLY: gcloud {command}")  # a write verb would fail the test run
        key = f"{command} {' '.join(map(str, arguments))}".strip()
        self.calls.append(f"{project}::{key}")
        for candidate in (f"{project}::{key}", f"{project}::{command}", key, command):
            if candidate in self.fixtures:
                value = self.fixtures[candidate]
                if isinstance(value, Err):
                    raise GcloudError(value.message, value.category)
                return copy.deepcopy(value)
        raise GcloudError(f"No fixture for gcloud {key}", "Other")


def healthy(project: str = PROJECT) -> dict:
    """Fixtures for a project that meets every check."""
    net = f"https://www.googleapis.com/compute/v1/projects/{project}/global/networks/vpc-main"
    fx = {
        "projects describe": {"projectId": project, "projectNumber": "123456789012", "name": "Test Project One", "lifecycleState": "ACTIVE",
                              "parent": {"type": "organization", "id": "111111111111"}},
        "projects get-iam-policy": {
            "bindings": [{"role": "roles/viewer", "members": ["user:alice@contoso.com", "group:ops@contoso.com"]},
                         {"role": "roles/storage.objectViewer", "members": [f"serviceAccount:{SA}"]}],
            "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}, {"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]},
        "iam service-accounts list": [{"email": SA, "displayName": "app"}],
        KEYS_KEY: [],
        "services api-keys list": [],
        "logging sinks list": [{"name": "all-logs", "destination": "storage.googleapis.com/log-archive", "filter": ""}],
        "storage buckets list": [
            {"name": "log-archive", "uniform_bucket_level_access": True, "public_access_prevention": "enforced",
             "retention_policy": {"retentionPeriod": "31536000", "isLocked": True}},
            {"name": "data-bucket", "uniform_bucket_level_access": True, "public_access_prevention": "inherited"}],
        "storage buckets get-iam-policy gs://data-bucket": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["group:ops@contoso.com"]}]},
        "compute networks list": [{"name": "vpc-main", "autoCreateSubnetworks": False}],
        "compute firewall-rules list": [{"name": "allow-iap-ssh", "network": net, "direction": "INGRESS", "disabled": False,
                                         "sourceRanges": ["35.235.240.0/20"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}],
        "compute networks subnets list": [{"name": "sn1", "region": f"https://www.googleapis.com/compute/v1/projects/{project}/regions/europe-west2",
                                           "purpose": "PRIVATE", "logConfig": {"enable": True}}],
        "dns managed-zones list": [{"name": "pub", "visibility": "public",
                                    "dnssecConfig": {"state": "on", "defaultKeySpecs": [{"keyType": "keySigning", "algorithm": "rsasha256"}]}}],
        "compute instances list": [{
            "name": "vm1", "zone": f"https://www.googleapis.com/compute/v1/projects/{project}/zones/europe-west2-a", "status": "RUNNING",
            "canIpForward": False, "networkInterfaces": [{"network": net, "accessConfigs": []}],
            "serviceAccounts": [{"email": SA, "scopes": ["https://www.googleapis.com/auth/logging.write"]}],
            "metadata": {"items": [{"key": "block-project-ssh-keys", "value": "TRUE"}]},
            "shieldedInstanceConfig": {"enableSecureBoot": True, "enableVtpm": True, "enableIntegrityMonitoring": True}}],
        "compute project-info describe": {"commonInstanceMetadata": {"items": [{"key": "enable-oslogin", "value": "TRUE"}]}},
        "sql instances list": [{"name": "db1", "instanceType": "CLOUD_SQL_INSTANCE",
                                "settings": {"ipConfiguration": {"ipv4Enabled": False, "sslMode": "ENCRYPTED_ONLY", "authorizedNetworks": []},
                                             "backupConfiguration": {"enabled": True}}}],
        "kms keyrings list --location=global": [{"name": f"projects/{project}/locations/global/keyRings/ring1"}],
        "kms keys list --keyring=ring1 --location=global": [{"name": f"projects/{project}/locations/global/keyRings/ring1/cryptoKeys/key1",
                                                              "purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776000s"}],
        "kms keys get-iam-policy key1 --keyring=ring1 --location=global": {"bindings": []},
        "auth list --filter=status:ACTIVE": [{"account": "assessor@contoso.com", "status": "ACTIVE"}],
    }
    for c in ("iam.disableServiceAccountKeyCreation", "storage.publicAccessPrevention", "compute.requireOsLogin", "sql.restrictPublicIp",
              "compute.skipDefaultNetworkCreation", "compute.disableSerialPortAccess", "iam.automaticIamGrantsForDefaultServiceAccounts"):
        fx[f"org-policies describe {c} --effective"] = {"spec": {"rules": [{"enforce": True}]}}
    fx["org-policies describe compute.vmExternalIpAccess --effective"] = {"spec": {"rules": [{"denyAll": True}]}}
    fx["org-policies describe iam.allowedPolicyMemberDomains --effective"] = {"spec": {"rules": [{"values": {"allowedValues": ["C0123abcd"]}}]}}
    return fx


def add_binding(fx: dict, role: str, *members: str) -> None:
    fx["projects get-iam-policy"]["bindings"].append({"role": role, "members": list(members)})
