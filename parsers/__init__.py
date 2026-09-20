"""Shared packet parsing pipeline for live traffic and PCAP input."""

from .pipeline import parse_packet

__all__ = ["parse_packet"]
