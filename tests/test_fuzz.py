"""Randomized property test: patterns must be mutually exclusive and
complete (every changed query covered exactly once, nothing else)."""
import random

import dns.name
import pytest

from app.impact import compute_impact, pattern_covers
from app.resolver import resolve
from app.zones import QUERY_TYPES, parse_origin, parse_zone

ORIGIN = parse_origin("example.com")
LABELS = ["a", "b", "c", "d"]


def random_name(rng, max_depth=3):
    depth = rng.randint(1, max_depth)
    return ".".join(rng.choice(LABELS) for _ in range(depth))


def random_zone(rng):
    """Build a random, valid zone (respecting all validation rules)."""
    records = {}  # name -> list of (type, rdata)

    def below_dname(name):
        parts = name.split(".")
        for i in range(1, len(parts)):
            ancestor = ".".join(parts[i:])
            if any(t == "DNAME" for t, _ in records.get(ancestor, [])):
                return True
        return False

    def add(name, rtype, rdata):
        records.setdefault(name, []).append((rtype, rdata))

    # a few wildcard owners
    owners = {random_name(rng) for _ in range(rng.randint(2, 7))}
    for _ in range(rng.randint(0, 2)):
        owners.add("*." + random_name(rng, 2))
    for name in sorted(owners):
        if below_dname(name):
            continue
        choice = rng.random()
        if choice < 0.45:
            add(name, "A", f"192.0.2.{rng.randint(1, 250)}")
            if rng.random() < 0.3:
                add(name, "AAAA", f"2001:db8::{rng.randint(1, 9999):x}")
        elif choice < 0.6:
            target = rng.choice(sorted(owners))
            if target != name and not below_dname(target):
                add(name, "CNAME", target)
        elif choice < 0.75 and name != "*" and not name.startswith("*."):
            # delegation (NS) - allowed to occlude, always valid here
            add(name, "NS", "ns1")
        elif choice < 0.9 and not name.startswith("*."):
            # DNAME: only if nothing below this name exists yet
            if not any(o != name and (o == name or o.endswith("." + name))
                       for o in owners):
                target = rng.choice(sorted(owners))
                if not below_dname(target):
                    add(name, "DNAME", target)
        else:
            add(name, "A", f"192.0.2.{rng.randint(1, 250)}")

    lines = ["$ORIGIN example.com.", "$TTL 300",
             "@ IN SOA ns1 admin 1 7200 3600 1209600 300",
             "@ IN NS ns1", "ns1 IN A 192.0.2.1"]
    for name in sorted(records):
        for rtype, rdata in records[name]:
            lines.append(f"{name} IN {rtype} {rdata}")
    return "\n".join(lines) + "\n"


def check_pair(base_text, cand_text):
    z1 = parse_zone(base_text, ORIGIN)
    z2 = parse_zone(cand_text, ORIGIN)
    patterns = compute_impact(z1, z2)
    union = z1.exist | z2.exist
    sample = set(union)
    for name in union:
        sample.add(dns.name.from_text("q1", name))
        sample.add(dns.name.from_text("q2.q1", name))
    for name in sample:
        for qtype in QUERY_TYPES:
            changed = resolve(z1, name, qtype) != resolve(z2, name, qtype)
            covering = [p for p in patterns if pattern_covers(p, name, qtype)]
            assert len(covering) <= 1, f"overlap at {name}/{qtype}"
            assert (len(covering) == 1) == changed, (
                f"coverage mismatch at {name}/{qtype}: changed={changed}\n"
                f"baseline: {resolve(z1, name, qtype)}\n"
                f"candidate: {resolve(z2, name, qtype)}\n"
                f"patterns: {patterns}")


@pytest.mark.parametrize("seed", range(40))
def test_random_zone_pairs(seed):
    rng = random.Random(seed)
    base = random_zone(rng)
    cand = random_zone(rng)
    check_pair(base, cand)
