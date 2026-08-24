"""A small, static hint table for ports that show up constantly on home
networks. This is not meant to be exhaustive — it's a cheap local nudge the
LLM prompt can lean on, not a replacement for it reasoning about the
device-class context around a flow."""

KNOWN_PORTS: dict[tuple[int, int], str] = {
    (6, 7000): "AirPlay",
    (6, 7001): "AirPlay",
    (17, 5353): "mDNS",
    (17, 1900): "SSDP/UPnP discovery",
    (6, 8009): "Chromecast",
    (6, 8443): "HTTPS (alt port)",
    (6, 445): "SMB file sharing",
    (6, 548): "AFP file sharing",
    (17, 123): "NTP",
    (17, 53): "DNS",
    (6, 53): "DNS",
    (6, 631): "IPP printing",
    (17, 631): "IPP printing",
    (6, 3689): "DAAP (iTunes/Music sharing)",
    (6, 5000): "UPnP / AirPlay (older)",
    (6, 8080): "HTTP (alt port)",
}


def describe_port(proto: int, port: int | None) -> str | None:
    if port is None:
        return None
    return KNOWN_PORTS.get((proto, port))
