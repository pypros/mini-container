import ipaddress
import logging
import random
import re
import sys
from pathlib import Path

from . import command

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


class NetworkGenerationError(RuntimeError):
    """Raised when a free subnet cannot be found after the maximum number of attempts."""

    pass


def get_used_subnets() -> set[ipaddress.IPv4Network]:
    """Retrieves a list of all subnets used on the host based on the routing table."""
    used_subnets: set[ipaddress.IPv4Network] = set()
    # Show all routes in CIDR format
    route_output = command.run_on_host(
        ["ip", "route", "show"], pipe_output=True, check_error=False
    )

    if not route_output:
        return used_subnets

    for line in route_output.splitlines():
        # We are interested in entries starting with an IP address (usually containing a mask)
        # Examples: 192.168.1.0/24, 10.0.0.0/8, 172.16.0.0/16

        # Search for an address in A.B.C.D/Mask format
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", line)

        if match:
            try:
                # Add the network to the set to avoid duplicates
                # ipaddress automatically normalizes the format (e.g., 192.168.1.5/24 -> 192.168.1.0/24)
                network = ipaddress.ip_network(match.group(1), strict=False)
                if isinstance(network, ipaddress.IPv4Network):
                    used_subnets.add(network)
            except ValueError:
                # Ignore invalid IP formats
                continue
    return used_subnets


def generate_network_config() -> dict[str, str]:
    """
    Generates a unique set of IP addresses that does not conflict with active host networks.
    Picks a random, private /16 subnet from the 172.16.0.0/12 range.
    """

    used_subnets = get_used_subnets()
    max_tries = 5

    # Private Class B range is 172.16.0.0/12, spanning 172.16.x.x to 172.31.x.x
    for _ in range(max_tries):
        # 1. Randomly select the second octet (16 to 31)
        random_second_octet = random.randint(16, 31)
        network_base = f"172.{random_second_octet}.0.0/16"

        try:
            new_net = ipaddress.ip_network(network_base)
        except ValueError:
            # Skip if the address is invalid for some reason
            continue

        # 2. Check for conflict
        is_conflicting = False
        for used_net in used_subnets:
            # Check if the new network (new_net) overlaps with any existing one
            if new_net.overlaps(used_net):
                # logger.warning(f"Randomly selected network {new_net} conflicts with {used_net}. Retrying...")
                is_conflicting = True
                break

        # If no conflict, return the configuration
        if not is_conflicting:
            # 3. Assign addresses
            # Bridge IP (Gateway) - The first usable address
            bridge_ip_full = ipaddress.IPv4Address(int(new_net.network_address) + 1)
            # Container IP - The second usable address
            container_ip_full = ipaddress.IPv4Address(int(new_net.network_address) + 2)

            return {
                "container_network": str(new_net),
                "bridge_ip": f"{bridge_ip_full}/{new_net.prefixlen}",
                "container_ip": f"{container_ip_full}/{new_net.prefixlen}",
            }
    raise NetworkGenerationError(
        f"Can't to find a free /16 subnet in the 172.16.0.0/12 range after {max_tries} attempts. "
        "Check the active network configuration (e.g., Docker, VPN, bridges) on the host."
    )


def host_interface(custom_bridge: str) -> str | None:
    route_output = command.run_on_host(
        ["ip", "route", "show", "default"], pipe_output=True, check_error=True
    )
    match = re.search(r"dev\s+(\S+)", route_output or "")
    if match:
        interface_name = match.group(1)
        logger.info(f"Found default interface: {interface_name}")
        if interface_name not in ("lo", custom_bridge):
            return interface_name
    return None


def create(
    container_pid: int,
    custom_bridge: str,
    container_root: str,
    bridge_ip: str,
    container_network: str,
    container_ip: str,
    host_interface: str,
) -> None:
    """Creates VETH, bridge, NAT, and configures the network using the container's PID.

    This function is optimized to reduce the number of external program calls to 8.
    """
    logger.info("--- CONFIGURING NETWORK (Host) ---")

    veth_host = f"h{container_pid}"
    veth_guest = f"c{container_pid}"
    gateway_ip = bridge_ip.split("/")[0]

    logger.info("1/8: Enabling IP Forwarding...")
    command.run_on_host(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])

    logger.info("2/8: Creating Bridge and assigning IP...")
    command.run_on_host(
        ["ip", "link", "add", "name", custom_bridge, "type", "bridge"],
        ignore_stderr=True,
        check_error=False,
    )
    command.run_on_host(["ip", "link", "set", custom_bridge, "up"])
    command.run_on_host(
        ["ip", "addr", "add", bridge_ip, "dev", custom_bridge],
        check_error=False,
        ignore_stderr=True,
    )

    logger.info("3/8: Creating VETH pair...")
    command.run_on_host(
        [
            "ip",
            "link",
            "add",
            "name",
            veth_host,
            "type",
            "veth",
            "peer",
            "name",
            veth_guest,
        ]
    )
    command.run_on_host(["ip", "link", "set", veth_host, "master", custom_bridge])
    command.run_on_host(["ip", "link", "set", veth_host, "up"])

    logger.info("4/8: Moving VETH to namespace...")
    command.run_on_host(["ip", "link", "set", veth_guest, "netns", str(container_pid)])

    logger.info("5/8: Configuring NAT (iptables)...")
    command.run_on_host(
        [
            "iptables",
            "-w",
            "-t",
            "nat",
            "-I",
            "POSTROUTING",
            "1",
            "-s",
            container_network,
            "-o",
            host_interface,
            "-j",
            "MASQUERADE",
        ]
    )
    command.run_on_host(
        [
            "iptables",
            "-w",
            "-I",
            "FORWARD",
            "1",
            "-i",
            custom_bridge,
            "-o",
            host_interface,
            "-j",
            "ACCEPT",
        ]
    )
    command.run_on_host(
        [
            "iptables",
            "-w",
            "-I",
            "FORWARD",
            "1",
            "-i",
            host_interface,
            "-o",
            custom_bridge,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ]
    )

    logger.info("6/8: Writing resolv.conf...")
    try:
        etc = Path(container_root) / "etc"
        resolv_conf = etc / "resolv.conf"
        resolv_conf.parent.mkdir(parents=True, exist_ok=True)
        with open(resolv_conf, "w") as f:
            f.write("nameserver 8.8.8.8\nnameserver 1.1.1.1\n")
    except Exception as e:
        logger.error(f"Error writing resolv.conf: {e}")
        sys.exit(1)

    logger.info("7/8: Configuring network inside container...")
    command.run_on_container(
        container_pid,
        f"""
            ip link set lo up && \
            ip link set {veth_guest} up && \
            ip addr add {container_ip} dev {veth_guest} && \
            ip route add default via {gateway_ip};
        """,
        Path(container_root),
    )

    logger.info("--- NETWORK CONFIGURATION COMPLETE ---")


def remove(
    custom_bridge: str,
    bridge_ip: str,
    container_network: str,
    host_interface: str,
) -> None:
    """Removes global network configurations (iptables, bridge)."""
    logger.info("--- CLEANING GLOBAL NETWORK CONFIGURATION ---")

    logger.info("1. Removing iptables rules...")
    command.run_on_host(
        [
            "iptables",
            "-w",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            container_network,
            "-o",
            host_interface,
            "-j",
            "MASQUERADE",
        ],
        check_error=False,
        ignore_stderr=True,
    )
    command.run_on_host(
        [
            "iptables",
            "-w",
            "-D",
            "FORWARD",
            "-i",
            custom_bridge,
            "-o",
            host_interface,
            "-j",
            "ACCEPT",
        ],
        check_error=False,
        ignore_stderr=True,
    )
    command.run_on_host(
        [
            "iptables",
            "-w",
            "-D",
            "FORWARD",
            "-i",
            host_interface,
            "-o",
            custom_bridge,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        check_error=False,
        ignore_stderr=True,
    )

    logger.info("Iptables rules removed.")

    if command.run_on_host(
        ["ip", "link", "show", custom_bridge], check_error=False, pipe_output=True
    ):
        logger.info(f"2. Removing bridge {custom_bridge}...")
        command.run_on_host(
            ["ip", "addr", "del", bridge_ip, "dev", custom_bridge],
            check_error=False,
            ignore_stderr=True,
        )
        command.run_on_host(
            ["ip", "link", "set", custom_bridge, "down"],
            check_error=False,
            ignore_stderr=True,
        )
        command.run_on_host(
            ["ip", "link", "del", custom_bridge], check_error=False, ignore_stderr=True
        )
        logger.info("Bridge removed.")
    else:
        logger.info("INFO: Bridge does not exist, skipping deletion.")
    logger.info("--- GLOBAL NETWORK CLEANUP COMPLETE ---")
