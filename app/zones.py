"""Parsing and validation of BIND master-file zone text.

Only SOA, NS, A, AAAA, CNAME, DNAME records and the $ORIGIN / $TTL
directives are supported.  A zone text is rejected (whole request fails)
when it is syntactically illegal, contains out-of-zone owner names or
refers to names outside the zone (external references in NS/CNAME/DNAME
rdata).
"""
from __future__ import annotations

import re

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.tokenizer
import dns.zone
import dns.zonefile

#: Record types supported by the service (also the queryable types).
SUPPORTED_TYPES = ("A", "AAAA", "CNAME", "DNAME", "NS", "SOA")

#: Types that can be queried through /resolve and are compared by /impact.
QUERY_TYPES = ["A", "AAAA", "CNAME", "DNAME", "NS", "SOA"]

#: Types whose rdata embeds a domain name that must stay inside the zone.
_FOLLOWED_TYPES = {"NS", "CNAME", "DNAME"}

_DIRECTIVE_RE = re.compile(r"^[ \t]*\$([A-Za-z]+)", re.MULTILINE)


class ZoneError(Exception):
    """The zone text is invalid, out-of-zone or refers outside the zone."""


class ZoneData:
    """A parsed and validated zone.

    nodes: dns.name.Name -> {rtype: (ttl, (rdata-string, ...))}
    exist: every owner name plus every empty non-terminal up to the apex.
    """

    __slots__ = ("origin", "nodes", "exist")

    def __init__(self, origin, nodes, exist):
        self.origin = origin
        self.nodes = nodes
        self.exist = exist


def parse_origin(text: str) -> dns.name.Name:
    try:
        name = dns.name.from_text(text.strip(), dns.name.root)
    except Exception as exc:  # noqa: BLE001 - normalised to ZoneError
        raise ZoneError(f"invalid origin {text!r}: {exc}") from exc
    return name


def _check_owner_names(text: str, origin: dns.name.Name) -> None:
    """Reject records whose owner name lies outside the zone.

    dns.zone.from_text silently drops out-of-zone lines, so the owner
    names are scanned explicitly (tracking $ORIGIN changes) beforehand.
    """
    current_origin = origin
    tokenizer = dns.tokenizer.Tokenizer(text)
    while True:
        token = tokenizer.get(want_leading=True)
        if token.is_eof():
            return
        if token.is_eol() or token.is_whitespace():
            continue  # blank line, or owner omitted (same as previous)
        value = token.value
        if value.startswith("$"):
            if value[1:].upper() == "ORIGIN":
                argument = tokenizer.get()
                try:
                    current_origin = dns.name.from_text(
                        argument.value, current_origin)
                except Exception as exc:  # noqa: BLE001
                    raise ZoneError(f"invalid $ORIGIN: {exc}") from exc
            _eat_logical_line(tokenizer)
            continue
        try:
            name = dns.name.from_text(value, current_origin)
        except Exception as exc:  # noqa: BLE001
            raise ZoneError(f"invalid owner name {value!r}: {exc}") from exc
        if not name.is_subdomain(origin):
            raise ZoneError(f"out-of-zone owner name: {name}")
        _eat_logical_line(tokenizer)


def _eat_logical_line(tokenizer) -> None:
    while True:
        token = tokenizer.get()
        if token.is_eol_or_eof():
            return


def parse_zone(text: str, origin: dns.name.Name) -> ZoneData:
    """Parse and validate one zone text; raise ZoneError on any problem."""
    if not isinstance(text, str) or not text.strip():
        raise ZoneError("zone text is empty")

    for match in _DIRECTIVE_RE.finditer(text):
        directive = match.group(1).upper()
        if directive not in ("ORIGIN", "TTL"):
            raise ZoneError(
                f"unsupported master-file directive ${match.group(1)} "
                "(only $ORIGIN and $TTL are allowed)"
            )

    _check_owner_names(text, origin)

    try:
        zone = dns.zone.from_text(
            text,
            origin=origin,
            relativize=False,
            allow_include=False,
            check_origin=False,
            allow_directives=["$ORIGIN", "$TTL"],
        )
    except dns.zonefile.CNAMEAndOtherData as exc:
        raise ZoneError(f"CNAME and other data: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - dnspython raises many types
        raise ZoneError(f"cannot parse zone: {exc}") from exc

    nodes = {}
    for name, node in zone.nodes.items():
        if not name.is_subdomain(origin):
            raise ZoneError(f"out-of-zone owner name: {name}")
        types = {}
        for rdataset in node.rdatasets:
            if rdataset.rdclass != dns.rdataclass.IN:
                raise ZoneError(f"non-IN record class at {name}")
            rtype = dns.rdatatype.to_text(rdataset.rdtype)
            if rtype not in SUPPORTED_TYPES:
                raise ZoneError(f"unsupported record type {rtype} at {name}")
            rdatas = []
            for rdata in rdataset:
                if rtype in _FOLLOWED_TYPES:
                    target = rdata.target
                    if not target.is_subdomain(origin):
                        raise ZoneError(
                            f"external reference {target} in {rtype} record at {name}"
                        )
                rdatas.append(rdata.to_text().lower())
            types[rtype] = (rdataset.ttl, tuple(sorted(rdatas)))
        nodes[name] = types

    apex = nodes.get(origin)
    if apex is None or "SOA" not in apex:
        raise ZoneError("zone has no SOA record at the apex")

    for name, types in nodes.items():
        if "SOA" in types:
            if name != origin:
                raise ZoneError(f"SOA record below the apex at {name}")
            if len(types["SOA"][1]) != 1:
                raise ZoneError("more than one SOA record at the apex")
        if "CNAME" in types:
            if len(types) > 1:
                raise ZoneError(f"CNAME and other data at {name}")
            if len(types["CNAME"][1]) != 1:
                raise ZoneError(f"more than one CNAME record at {name}")
        if "DNAME" in types:
            if len(types["DNAME"][1]) != 1:
                raise ZoneError(f"more than one DNAME record at {name}")
            if "NS" in types and name != origin:
                raise ZoneError(f"DNAME at delegation point {name}")

    # No data may exist below a DNAME node (RFC 6672).
    for dname_node in [n for n, t in nodes.items() if "DNAME" in t]:
        for name in nodes:
            if name != dname_node and name.is_subdomain(dname_node):
                raise ZoneError(
                    f"data below DNAME node {dname_node}: {name}"
                )

    exist = set()
    for name in nodes:
        current = name
        while True:
            exist.add(current)
            if current == origin:
                break
            current = current.parent()

    return ZoneData(origin, nodes, exist)
