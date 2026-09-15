"""Packet capture entry points for the IDS project."""

from collections.abc import Callable
from typing import Any

from scapy.all import Packet, sniff


PacketHandler = Callable[[Packet], Any]


def Capture_through_interface(
    interface: str,
    packet_handler: PacketHandler,
    *,
    count: int = 0,
    timeout: int | None = None,
    packet_filter: str | None = None,
) -> None:
   
    if not interface or not interface.strip():
        raise ValueError("interface must not be empty")
    if not callable(packet_handler):
        raise ValueError("packet_handler must be callable")
    if count < 0:
        raise ValueError("count must be zero or greater")
    if timeout is not None and timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    sniff(
        iface=interface,
        prn=packet_handler,
        count=count,
        timeout=timeout,
        filter=packet_filter,
        store=False,
    )


def Capture_through_pcap(
    pcap_file: str,
    packet_handler: PacketHandler,
    *,
    count: int = 0,
) -> None:

    if not pcap_file or not pcap_file.strip():
        raise ValueError("pcap_file must not be empty")
    if not callable(packet_handler):
        raise ValueError("packet_handler must be callable")
    if count < 0:
        raise ValueError("count must be zero or greater")

    sniff(
        offline=pcap_file,
        prn=packet_handler,
        count=count,
        store=False,
    )
