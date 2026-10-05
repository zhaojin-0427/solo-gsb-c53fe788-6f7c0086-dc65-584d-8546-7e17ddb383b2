"""Offline, deterministic resolution of one name/type against one zone.

The resolver never touches the network.  It implements exactly the
semantics the service compares:

* delegations (non-apex NS nodes) answer with a referral,
* empty non-terminals answer NODATA (``nodata-ent``),
* the closest-encloser wildcard synthesises answers,
* CNAME/DNAME rewrite the query and are re-evaluated hop by hop,
  DNAME synthesises a CNAME,
* alias loops are detected and reported as ``alias-loop``.
"""
from __future__ import annotations

from dataclasses import dataclass

import dns.name

from .zones import ZoneData

#: Maximum number of CNAME/DNAME hops before the chain is declared a loop.
MAX_HOPS = 32


@dataclass(frozen=True)
class Response:
    """One deterministic answer.

    rcode:       "NOERROR" or "NXDOMAIN"
    termination: exact | nodata | nodata-ent | wildcard | nodata-wildcard |
                 nxdomain | delegation | alias-loop
    answers:     answer records (chain order, each rrset canonically sorted)
    authority:   referral NS records (only for termination "delegation")
    """

    rcode: str
    termination: str
    answers: tuple = ()
    authority: tuple = ()

    def to_dict(self):
        return {
            "rcode": self.rcode,
            "termination": self.termination,
            "answers": list(self.answers),
            "authority": list(self.authority),
        }


def _records(name: dns.name.Name, rtype: str, rrset) -> tuple:
    ttl, rdatas = rrset
    owner = str(name).lower()
    return tuple(f"{owner} {ttl} IN {rtype} {rdata}" for rdata in rdatas)


def _target(rrset) -> dns.name.Name:
    return dns.name.from_text(rrset[1][0])


def resolve(zone: ZoneData, qname: dns.name.Name, qtype: str) -> Response:
    """Resolve ``qname``/``qtype`` against ``zone`` without any network I/O."""
    chain = []
    visited = set()
    current = qname

    for _ in range(MAX_HOPS):
        if (current, qtype) in visited:
            return Response("NOERROR", "alias-loop", tuple(chain), ())
        visited.add((current, qtype))

        # 1. Deepest zone cut (non-apex NS) at or above the current name.
        walk = current
        delegation = None
        while walk != zone.origin:
            types = zone.nodes.get(walk)
            if types is not None and "NS" in types:
                delegation = walk
                break
            walk = walk.parent()
        if delegation is not None:
            authority = _records(delegation, "NS", zone.nodes[delegation]["NS"])
            return Response("NOERROR", "delegation", tuple(chain), authority)

        types = zone.nodes.get(current)
        if current in zone.exist:
            # 2. Exact match.
            if types and "CNAME" in types and qtype != "CNAME":
                chain.extend(_records(current, "CNAME", types["CNAME"]))
                current = _target(types["CNAME"])
                continue
            if types and qtype in types:
                answers = tuple(chain) + _records(current, qtype, types[qtype])
                return Response("NOERROR", "exact", answers, ())
            if types:
                return Response("NOERROR", "nodata", tuple(chain), ())
            return Response("NOERROR", "nodata-ent", tuple(chain), ())

        # 3. DNAME at a strict ancestor (deepest first, apex included):
        #    synthesise a CNAME and restart at the rewritten name.
        redirected = False
        walk = current.parent()
        while True:
            types = zone.nodes.get(walk)
            if types and "DNAME" in types:
                chain.extend(_records(walk, "DNAME", types["DNAME"]))
                target = _target(types["DNAME"])
                synthesised = current.relativize(walk) + target
                ttl = types["DNAME"][0]
                chain.append(
                    f"{str(current).lower()} {ttl} IN CNAME "
                    f"{str(synthesised).lower()}"
                )
                current = synthesised
                redirected = True
                break
            if walk == zone.origin:
                break
            walk = walk.parent()
        if redirected:
            continue

        # 4. Closest encloser and its wildcard.
        encloser = current.parent()
        while encloser not in zone.exist:
            encloser = encloser.parent()
        wildcard = dns.name.from_text("*", encloser)
        wtypes = zone.nodes.get(wildcard)
        if wtypes is not None:
            if "CNAME" in wtypes and qtype != "CNAME":
                chain.extend(_records(current, "CNAME", wtypes["CNAME"]))
                current = _target(wtypes["CNAME"])
                continue
            if qtype in wtypes:
                answers = tuple(chain) + _records(current, qtype, wtypes[qtype])
                return Response("NOERROR", "wildcard", answers, ())
            return Response("NOERROR", "nodata-wildcard", tuple(chain), ())

        # 5. Nothing matched.
        return Response("NXDOMAIN", "nxdomain", tuple(chain), ())

    return Response("NOERROR", "alias-loop", tuple(chain), ())
