"""Change-impact engine: computes mutually exclusive, complete patterns.

The in-zone query space (every possible qname below the apex x every
supported qtype) is partitioned into:

* ``exact`` entries  - names existing in at least one version
                       (owners and empty non-terminals), and
* ``gap`` entries    - all non-existing names whose closest existing
                       ancestor (in the union of both zones) is ``a``;
                       rendered as ``**.a`` minus ``a`` itself minus the
                       subtrees of the children of ``a``.

A whole gap behaves uniformly (modulo the owner name) except when an
*unchanged* DNAME redirects it: then every query is rewritten into the
DNAME target subtree, so changes under the target are mapped back into
the redirected subtree ("propagation").  That is how changes of unlisted
names below a DNAME target are covered.

Patterns are grouped by (shape, rcode/termination transition); every
pattern carries a witness name and both versions' answers.
"""
from __future__ import annotations

from dataclasses import dataclass

import dns.name

from .resolver import Response, resolve
from .zones import QUERY_TYPES, ZoneData

#: Safety cap on the number of change entries (pathological DNAME cycles).
MAX_ENTRIES = 20000


@dataclass
class Entry:
    kind: str            # "exact" | "gap"
    base: dns.name.Name  # exact name, or closest-encloser of the gap
    excl: tuple          # (("exact"|"subtree", Name), ...) exclusions
    qtype: str
    witness: dns.name.Name
    r1: Response
    r2: Response


def _swap(name: dns.name.Name, old: dns.name.Name, new: dns.name.Name):
    """Replace the ``old`` suffix of ``name`` with ``new``."""
    return name.relativize(old) + new


def _render_name(name: dns.name.Name) -> str:
    """Render a name for a pattern, escaping literal ``*`` labels as ``\\*``.

    Keeps the pattern language unambiguous: a leading ``*.`` or ``**.``
    is always a glob operator, never a literal wildcard owner label.
    """
    parts = []
    for label in name.labels:
        if not label:
            continue
        if label == b"*":
            parts.append("\\*")
        else:
            parts.append(dns.name.Name([label, b""]).to_text()[:-1])
    return ".".join(parts).lower() + "."


def _dname_env(zone: ZoneData, name: dns.name.Name):
    """Effective DNAME applying to strict descendants of ``name``.

    Returns (dname-owner, target-string) or None.  A delegation found
    while walking up occludes anything below it.
    """
    current = name
    found = None
    while True:
        types = zone.nodes.get(current)
        if types is not None:
            if current != zone.origin and "NS" in types:
                return None
            if found is None and "DNAME" in types:
                found = (current, types["DNAME"][1][0])
        if current == zone.origin:
            break
        current = current.parent()
    return found


def _fresh_label(base: dns.name.Name, child_names) -> str:
    used = {str(child.relativize(base)) for child in child_names}
    counter = 0
    while True:
        label = f"zz-impact-{counter}"
        if label not in used:
            return label
        counter += 1


def compute_entries(z1: ZoneData, z2: ZoneData) -> list:
    """All changed (shape, qtype) entries of the two zones."""
    origin = z1.origin
    union = z1.exist | z2.exist
    children = {name: [] for name in union}
    for name in union:
        if name != origin:
            children[name.parent()].append(name)

    entries: list[Entry] = []

    # 1. Names existing in at least one version.
    for name in sorted(union, key=str):
        for qtype in QUERY_TYPES:
            r1 = resolve(z1, name, qtype)
            r2 = resolve(z2, name, qtype)
            if r1 != r2:
                entries.append(Entry("exact", name, (), qtype, name, r1, r2))

    # 2. Gaps: non-existing names, grouped by closest existing ancestor.
    for name in sorted(union, key=str):
        env1 = _dname_env(z1, name)
        env2 = _dname_env(z2, name)
        if env1 is not None and env1 == env2:
            continue  # unchanged active DNAME: handled by propagation
        label = _fresh_label(name, children[name])
        rep = dns.name.from_text(label, name)
        excl = (("exact", name),) + tuple(
            ("subtree", child) for child in sorted(children[name], key=str)
        )
        for qtype in QUERY_TYPES:
            r1 = resolve(z1, rep, qtype)
            r2 = resolve(z2, rep, qtype)
            if r1 != r2:
                entries.append(Entry("gap", name, excl, qtype, rep, r1, r2))

    # 3. Propagation through DNAMEs that are active and identical in both
    #    versions: a change at m below the target reappears at the
    #    rewritten name below the DNAME owner.
    dmaps = []
    for name in union:
        env = _dname_env(z1, name)
        if env is not None and env[0] == name and _dname_env(z2, name) == env:
            dmaps.append((name, dns.name.from_text(env[1])))

    seen = {(e.kind, e.base, e.qtype) for e in entries}
    queue = list(entries)
    while queue:
        entry = queue.pop(0)
        for owner, target in dmaps:
            if entry.kind == "exact":
                if entry.base == target or not entry.base.is_subdomain(target):
                    continue
                new_base = _swap(entry.base, target, owner)
                key = ("exact", new_base, entry.qtype)
                if key in seen:
                    continue
                seen.add(key)
                new_entry = Entry(
                    "exact", new_base, (), entry.qtype, new_base,
                    resolve(z1, new_base, entry.qtype),
                    resolve(z2, new_base, entry.qtype),
                )
            else:
                if not entry.base.is_subdomain(target):
                    continue
                new_base = _swap(entry.base, target, owner)
                key = ("gap", new_base, entry.qtype)
                if key in seen:
                    continue
                seen.add(key)
                new_excl = tuple(
                    (kind, _swap(x, target, owner)) for kind, x in entry.excl
                )
                new_witness = _swap(entry.witness, target, owner)
                new_entry = Entry(
                    "gap", new_base, new_excl, entry.qtype, new_witness,
                    resolve(z1, new_witness, entry.qtype),
                    resolve(z2, new_witness, entry.qtype),
                )
            entries.append(new_entry)
            queue.append(new_entry)
            if len(entries) > MAX_ENTRIES:
                return entries
    return entries


def render_patterns(entries: list) -> list:
    """Group entries into the mutually exclusive pattern objects."""
    order = {qtype: i for i, qtype in enumerate(QUERY_TYPES)}
    entries = sorted(
        entries,
        key=lambda e: (str(e.base).lower(), 0 if e.kind == "exact" else 1,
                       order[e.qtype]),
    )
    groups = {}
    for entry in entries:
        signature = (
            entry.kind,
            str(entry.base).lower(),
            entry.excl,
            entry.r1.rcode,
            entry.r1.termination,
            entry.r2.rcode,
            entry.r2.termination,
        )
        groups.setdefault(signature, []).append(entry)

    patterns = []
    for group in groups.values():
        group.sort(key=lambda e: order[e.qtype])
        first = group[0]
        if first.kind == "exact":
            match = _render_name(first.base)
        else:
            match = "**." + _render_name(first.base)
        exclude = [
            _render_name(x) if kind == "exact" else "**." + _render_name(x)
            for kind, x in first.excl
        ]
        patterns.append({
            "id": 0,  # assigned below
            "match": match,
            "exclude": exclude,
            "types": [e.qtype for e in group],
            "baseline": {
                "rcode": first.r1.rcode,
                "termination": first.r1.termination,
            },
            "candidate": {
                "rcode": first.r2.rcode,
                "termination": first.r2.termination,
            },
            "witness": {
                "name": str(first.witness).lower(),
                "type": first.qtype,
                "baseline": first.r1.to_dict(),
                "candidate": first.r2.to_dict(),
            },
        })
    for index, pattern in enumerate(patterns, 1):
        pattern["id"] = index
    return patterns


def compute_impact(z1: ZoneData, z2: ZoneData) -> list:
    return render_patterns(compute_entries(z1, z2))


def pattern_covers(pattern: dict, name: dns.name.Name, qtype: str) -> bool:
    """True when ``pattern`` (its match + exclude + types) covers the query."""
    if qtype not in pattern["types"]:
        return False
    match = pattern["match"]
    if match.startswith("**."):
        base = dns.name.from_text(match[3:])
        ok = name.is_subdomain(base)
    elif match.startswith("*."):
        base = dns.name.from_text(match[2:])
        ok = name.parent() == base
    else:
        ok = name == dns.name.from_text(match)
    if not ok:
        return False
    for exclusion in pattern.get("exclude", []):
        if exclusion.startswith("**."):
            if name.is_subdomain(dns.name.from_text(exclusion[3:])):
                return False
        elif exclusion.startswith("*."):
            if name.parent() == dns.name.from_text(exclusion[2:]):
                return False
        elif name == dns.name.from_text(exclusion):
            return False
    return True
