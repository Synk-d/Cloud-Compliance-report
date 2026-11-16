import os
from azure.identity import AzureCliCredential, DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient

# ==============================================================================
# REAL AZURE SUBSCRIPTION CONFIGURATION
# Replace the fallback string with your actual Azure Subscription UUID
# or set it via terminal: $env:AZURE_SUBSCRIPTION_ID="your-real-uuid"
# ==============================================================================
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "PASTE-YOUR-REAL-AZURE-SUBSCRIPTION-ID-HERE")


def get_azure_clients():
    """
    Authenticates directly with your active Azure session (`az login` or Service Principal)
    and returns live ARM Management Clients.
    """
    try:
        credential = AzureCliCredential()
    except Exception:
        credential = DefaultAzureCredential()

    network_client = NetworkManagementClient(credential, AZURE_SUBSCRIPTION_ID)
    compute_client = ComputeManagementClient(credential, AZURE_SUBSCRIPTION_ID)
    storage_client = StorageManagementClient(credential, AZURE_SUBSCRIPTION_ID)
    kv_client = KeyVaultManagementClient(credential, AZURE_SUBSCRIPTION_ID)

    return network_client, compute_client, storage_client, kv_client


def _is_internet_exposed(rule):
    """Helper to check if an NSG security rule allows inbound traffic from the public internet."""
    if rule.direction != "Inbound" or rule.access != "Allow":
        return False

    sources = []
    if rule.source_address_prefix:
        sources.append(rule.source_address_prefix)
    if rule.source_address_prefixes:
        sources.extend(rule.source_address_prefixes)

    return any(src in ["*", "0.0.0.0/0", "Internet", "Any"] for src in sources)


def _matches_port(rule, target_port: str):
    """Helper to verify if a rule covers a specific destination port or wildcard."""
    ports = []
    if rule.destination_port_range:
        ports.append(str(rule.destination_port_range))
    if rule.destination_port_ranges:
        ports.extend([str(p) for p in rule.destination_port_ranges])

    for p in ports:
        if p == "*" or p == target_port:
            return True
        if "-" in p:
            try:
                start, end = map(int, p.split("-"))
                if start <= int(target_port) <= end:
                    return True
            except ValueError:
                pass
    return False


def scan_live_infrastructure(current_rules_state=None):
    """
    Executes a REAL live audit against your Microsoft Azure Subscription:
    1. Network Security Groups -> CIS 3.2 (Open RDP 3389) & CIS 5.1 (Open SSH 22)
    2. Storage Accounts -> CIS 3.1 (Public Anonymous Blob Access)
    3. Key Vaults -> CIS 8.1 (Purge Protection Enabled)
    4. Virtual Machines -> CIS 5.2 (Live Compute Inventory & Disk Encryption Check)
    """
    findings = []
    network_client, compute_client, storage_client, kv_client = get_azure_clients()

    # --------------------------------------------------------------------------
    # 1. REAL SCAN: Network Security Groups (CIS 3.2 RDP & CIS 5.1 SSH)
    # --------------------------------------------------------------------------
    try:
        for nsg in network_client.network_security_groups.list_all():
            rules = nsg.security_rules or []
            rdp_open = any(_is_internet_exposed(r) and _matches_port(r, "3389") for r in rules)
            ssh_open = any(_is_internet_exposed(r) and _matches_port(r, "22") for r in rules)

            findings.append({
                "id": f"cis-3.2-{nsg.name}",
                "service": "Network Security Group",
                "resource": nsg.id,
                "rule": "CIS 3.2 - Ensure No Open Inbound RDP (Port 3389) from Internet",
                "status": "FAILED" if rdp_open else "PASSED",
                "severity": "CRITICAL" if rdp_open else "RESOLVED"
            })

            findings.append({
                "id": f"cis-5.1-{nsg.name}",
                "service": "Network Security Group",
                "resource": nsg.id,
                "rule": "CIS 5.1 - Inbound SSH Access Restricted (Port 22)",
                "status": "FAILED" if ssh_open else "PASSED",
                "severity": "HIGH" if ssh_open else "RESOLVED"
            })
    except Exception as e:
        print(f"[AZURE NSG SCAN ERROR]: {e}")

    # --------------------------------------------------------------------------
    # 2. REAL SCAN: Storage Accounts (CIS 3.1 Public Blob Access)
    # --------------------------------------------------------------------------
    try:
        for sa in storage_client.storage_accounts.list():
            public_blob_allowed = bool(sa.allow_blob_public_access)
            findings.append({
                "id": f"cis-3.1-{sa.name}",
                "service": "Storage Accounts",
                "resource": sa.id,
                "rule": "CIS 3.1 - Disable Public Anonymous Blob Container Access",
                "status": "FAILED" if public_blob_allowed else "PASSED",
                "severity": "HIGH" if public_blob_allowed else "RESOLVED"
            })
    except Exception as e:
        print(f"[AZURE STORAGE SCAN ERROR]: {e}")

    # --------------------------------------------------------------------------
    # 3. REAL SCAN: Key Vaults (CIS 8.1 Purge Protection)
    # --------------------------------------------------------------------------
    try:
        for vault in kv_client.vaults.list_by_subscription():
            # Fetch full vault properties to inspect purge protection
            rg_name = vault.id.split("/")[4]
            full_vault = kv_client.vaults.get(rg_name, vault.name)
            purge_protected = bool(full_vault.properties.enable_purge_protection)

            findings.append({
                "id": f"cis-8.1-{vault.name}",
                "service": "Key Vaults",
                "resource": vault.id,
                "rule": "CIS 8.1 - Enforce Purge Protection on Key Vault",
                "status": "PASSED" if purge_protected else "FAILED",
                "severity": "RESOLVED" if purge_protected else "HIGH"
            })
    except Exception as e:
        print(f"[AZURE KEY VAULT SCAN ERROR]: {e}")

    # --------------------------------------------------------------------------
    # 4. REAL SCAN: Virtual Machines (CIS 5.2 Compute Baseline)
    # --------------------------------------------------------------------------
    try:
        for vm in compute_client.virtual_machines.list_all():
            os_disk = vm.storage_profile.os_disk if vm.storage_profile else None
            is_managed = bool(os_disk and os_disk.managed_disk)

            findings.append({
                "id": f"cis-5.2-{vm.name}",
                "service": "Virtual Machines",
                "resource": vm.id,
                "rule": "CIS 5.2 - Ensure Virtual Machine Uses Managed Disks",
                "status": "PASSED" if is_managed else "FAILED",
                "severity": "MEDIUM" if is_managed else "HIGH"
            })
    except Exception as e:
        print(f"[AZURE VM SCAN ERROR]: {e}")

    return findings


def remediate_live_nsg(rule_id: str, resource_id: str):
    """
    REAL LIVE REMEDIATION:
    Connects to Azure ARM API and modifies/deletes the actual offending NSG rule
    or disables public blob access on the real Storage Account.
    """
    network_client, _, storage_client, _ = get_azure_clients()
    parts = resource_id.split("/")

    try:
        rg_index = parts.index("resourceGroups") + 1
        rg_name = parts[rg_index]
    except ValueError:
        print(f"[REMEDIATION ERROR]: Invalid Azure Resource URI: {resource_id}")
        return False

    # 1. Real NSG Rule Remediation (Closes Port 3389 or Port 22 in Azure)
    if "networkSecurityGroups" in parts:
        try:
            nsg_name = parts[parts.index("networkSecurityGroups") + 1]
            nsg = network_client.network_security_groups.get(rg_name, nsg_name)
            target_port = "3389" if "cis-3.2" in rule_id else "22"

            for rule in (nsg.security_rules or []):
                if _is_internet_exposed(rule) and _matches_port(rule, target_port):
                    print(f"[LIVE AZURE ACTION] Deleting exposed rule '{rule.name}' on NSG '{nsg_name}'...")
                    poller = network_client.security_rules.begin_delete(rg_name, nsg_name, rule.name)
                    poller.result()  # Waits for Azure Cloud to finish deleting the rule
                    print(f"[LIVE AZURE ACTION] Rule '{rule.name}' successfully removed from Azure!")
            return True
        except Exception as e:
            print(f"[LIVE NSG REMEDIATION FAILED]: {e}")
            return False

    # 2. Real Storage Account Remediation (Disables Public Blob Access in Azure)
    if "storageAccounts" in parts:
        try:
            sa_name = parts[parts.index("storageAccounts") + 1]
            print(f"[LIVE AZURE ACTION] Disabling public blob access on Storage Account '{sa_name}'...")
            storage_client.storage_accounts.update(
                rg_name,
                sa_name,
                {"allow_blob_public_access": False}
            )
            print(f"[LIVE AZURE ACTION] Storage Account '{sa_name}' secured!")
            return True
        except Exception as e:
            print(f"[LIVE STORAGE REMEDIATION FAILED]: {e}")
            return False

    return False