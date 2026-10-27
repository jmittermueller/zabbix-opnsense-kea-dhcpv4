#!/usr/local/bin/python3
"""
Zabbix monitoring for OPNsense Kea DHCPv4 pools.

The script reads the active Kea DHCPv4 configuration and all IPv4 leases
through OPNsense's existing Kea control library. It outputs one compact JSON
object for a Zabbix master item and low-level discovery.

No API key, HTTP request, or direct access to the lease database is required.
"""

import ipaddress
import json
import os
import sys


KEA_SCRIPT_DIR = "/usr/local/opnsense/scripts/kea"

if KEA_SCRIPT_DIR not in sys.path:
    sys.path.insert(0, KEA_SCRIPT_DIR)

try:
    from lib.kea_ctrl import KeaCtrl
except Exception as exc:
    print(json.dumps({"error": f"Unable to load OPNsense Kea library: {exc}"}, separators=(",", ":")))
    sys.exit(1)


def fail(message):
    """Return a JSON error for Zabbix and terminate with a non-zero status."""
    print(json.dumps({"error": str(message)}, separators=(",", ":")))
    sys.exit(1)


def send_kea_command(command, arguments=None):
    """Run a command against the local Kea DHCPv4 service."""
    response = KeaCtrl.send_command(command, arguments, "dhcp4")

    if not isinstance(response, dict):
        fail(f"Kea command '{command}' returned no valid JSON object")

    result = response.get("result", 0)

    # Kea returns result 3 (empty) when lease4-get-all finds no leases.
    # This is a valid monitoring result, not an error.
    if result == 3 and command == "lease4-get-all":
        return {"result": 0, "arguments": {"leases": []}}

    if result != 0:
        text = response.get("text", "unknown Kea error")
        fail(f"Kea command '{command}' failed: {text}")

    return response


def parse_pool(pool_value):
    """Convert a Kea pool definition into first and last IPv4 addresses."""
    if isinstance(pool_value, dict):
        pool_value = pool_value.get("pool", "")

    pool_text = str(pool_value).strip()
    if not pool_text:
        raise ValueError("empty pool definition")

    if "-" in pool_text:
        start_text, end_text = [part.strip() for part in pool_text.split("-", 1)]
        start = ipaddress.IPv4Address(start_text)
        end = ipaddress.IPv4Address(end_text)
    else:
        network = ipaddress.IPv4Network(pool_text, strict=False)
        start = network.network_address
        end = network.broadcast_address

    if int(end) < int(start):
        raise ValueError(f"pool end precedes pool start: {pool_text}")

    return start, end


def main():
    config_response = send_kea_command("config-get")
    dhcp4_config = config_response.get("arguments", {}).get("Dhcp4", {})
    subnets = dhcp4_config.get("subnet4", [])

    if not isinstance(subnets, list):
        fail("Kea configuration does not contain a valid subnet4 list")

    subnet_ids = [subnet.get("id") for subnet in subnets if subnet.get("id") is not None]

    leases = []
    if subnet_ids:
        lease_response = send_kea_command("lease4-get-all", {"subnets": subnet_ids})
        leases = lease_response.get("arguments", {}).get("leases", [])

    leased_addresses = set()
    for lease in leases:
        address = lease.get("ip-address")
        if not address:
            continue

        try:
            leased_addresses.add(ipaddress.IPv4Address(address))
        except ipaddress.AddressValueError:
            continue

    result_pools = []

    for subnet in subnets:
        subnet_id = str(subnet.get("id", ""))
        subnet_cidr = str(subnet.get("subnet", ""))
        pools = subnet.get("pools", [])

        if not isinstance(pools, list):
            continue

        for pool_index, pool_definition in enumerate(pools, start=1):
            try:
                pool_start, pool_end = parse_pool(pool_definition)
            except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
                fail(f"Invalid pool in subnet {subnet_cidr}: {exc}")

            pool_size = int(pool_end) - int(pool_start) + 1
            used = sum(
                1
                for address in leased_addresses
                if int(pool_start) <= int(address) <= int(pool_end)
            )
            free = max(0, pool_size - used)
            usage_percent = round((used / pool_size) * 100, 2) if pool_size else 0.0

            pool_id = f"{subnet_id}-{pool_start}-{pool_end}"

            result_pools.append(
                {
                    "id": pool_id,
                    "subnet_id": subnet_id,
                    "subnet": subnet_cidr,
                    "pool_index": pool_index,
                    "pool": f"{pool_start} - {pool_end}",
                    "start": str(pool_start),
                    "end": str(pool_end),
                    "size": pool_size,
                    "used": used,
                    "free": free,
                    "usage_percent": usage_percent,
                }
            )

    print(json.dumps({"pools": result_pools}, separators=(",", ":"), sort_keys=False))


if __name__ == "__main__":
    main()
