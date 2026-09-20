"""Distinguish missing packet data from an invalid header."""


class IncompletePacket(ValueError):
    """The packet needs more captured bytes or stream/fragment reassembly."""


class UnsupportedProtocol(ValueError):
    """The packet uses a protocol outside the assignment's scope."""
