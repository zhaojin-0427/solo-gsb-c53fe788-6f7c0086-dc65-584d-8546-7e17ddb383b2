import dns.name
import pytest

from app.impact import compute_impact, pattern_covers
from app.resolver import resolve
from app.zones import QUERY_TYPES, parse_origin, parse_zone

ORIGIN = parse_origin("example.com")

BASELINE = """
$ORIGIN example.com.
$TTL 300
@      IN SOA ns1 admin 100 7200 3600 1209600 300
@      IN NS  ns1
ns1    IN A   192.0.2.1
www    IN A   192.0.2.10
api    IN CNAME www
sub    IN NS  ns1
d      IN DNAME target
target IN A   192.0.2.30
"""

CANDIDATE = """
$ORIGIN example.com.
$TTL 300
@      IN SOA ns1 admin 101 7200 3600 1209600 300
@      IN NS  ns1
ns1    IN A   192.0.2.1
www    IN A   192.0.2.99
api    IN CNAME www
sub    IN NS  ns1
d      IN DNAME target
target IN A   192.0.2.30
blog   IN A   192.0.2.50
x.target IN A 192.0.2.31
"""


def impact(base_text, cand_text):
    z1 = parse_zone(base_text, ORIGIN)
    z2 = parse_zone(cand_text, ORIGIN)
    return compute_impact(z1, z2), z1, z2


def by_match(patterns):
    result = {}
    for p in patterns:
        result.setdefault(p["match"], []).append(p)
    return result


def test_identical_zones_no_patterns():
    patterns, _, _ = impact(BASELINE, BASELINE)
    assert patterns == []


def test_serial_change_only():
    cand = BASELINE.replace("admin 100", "admin 101")
    patterns, _, _ = impact(BASELINE, cand)
    assert len(patterns) == 1
    p = patterns[0]
    assert p["match"] == "example.com."
    assert p["types"] == ["SOA"]
    assert p["baseline"]["termination"] == "exact"
    assert p["candidate"]["termination"] == "exact"


def test_a_change_and_cname_follower():
    patterns, _, _ = impact(BASELINE, CANDIDATE)
    grouped = by_match(patterns)
    # www itself
    www = grouped["www.example.com."]
    assert any(p["types"] == ["A"] for p in www)
    # api is a CNAME to www: its A answer follows the chain
    api = grouped["api.example.com."]
    assert any(p["types"] == ["A"] for p in api)
    wit = [p for p in api if p["types"] == ["A"]][0]["witness"]
    assert "192.0.2.10" in wit["baseline"]["answers"][-1]
    assert "192.0.2.99" in wit["candidate"]["answers"][-1]


def test_new_name_patterns():
    patterns, _, _ = impact(BASELINE, CANDIDATE)
    grouped = by_match(patterns)
    blog = grouped["blog.example.com."]
    transitions = {tuple(p["types"]): (p["baseline"]["termination"],
                                      p["candidate"]["termination"])
                   for p in blog}
    assert ("A",) in [tuple(k) for k in transitions]
    # A: NXDOMAIN -> exact ; other types: NXDOMAIN -> nodata
    a_pat = [p for p in blog if p["types"] == ["A"]][0]
    assert a_pat["baseline"]["rcode"] == "NXDOMAIN"
    assert a_pat["candidate"]["termination"] == "exact"
    rest = [p for p in blog if "AAAA" in p["types"]][0]
    assert rest["candidate"]["termination"] == "nodata"


def test_dname_target_subtree_propagation():
    """x.target is new; x.d is unlisted but must be covered."""
    patterns, _, _ = impact(BASELINE, CANDIDATE)
    grouped = by_match(patterns)
    assert "x.target.example.com." in grouped
    assert "x.d.example.com." in grouped
    pat = [p for p in grouped["x.d.example.com."] if p["types"] == ["A"]][0]
    wit = pat["witness"]
    assert wit["name"] == "x.d.example.com."
    assert wit["baseline"]["rcode"] == "NXDOMAIN"
    assert wit["candidate"]["termination"] == "exact"
    assert wit["candidate"]["answers"][0].startswith(
        "d.example.com. 300 IN DNAME")
    assert "192.0.2.31" in wit["candidate"]["answers"][-1]


def test_wildcard_addition_covers_gap():
    cand = BASELINE + "*.wild IN A 192.0.2.60\n"
    patterns, _, _ = impact(BASELINE, cand)
    grouped = by_match(patterns)
    assert "**.wild.example.com." in grouped
    gap = grouped["**.wild.example.com."][0]
    assert "wild.example.com." in gap["exclude"]
    assert "**." + "\\" + "*.wild.example.com." in gap["exclude"]
    assert gap["baseline"]["termination"] == "nxdomain"
    assert gap["candidate"]["termination"] == "wildcard"
    # the wildcard owner itself is an exact pattern (literal * is escaped)
    assert "\\*.wild.example.com." in grouped


def test_ent_becomes_nodata_ent():
    cand = BASELINE + "a.b.c IN A 192.0.2.70\n"
    patterns, _, _ = impact(BASELINE, cand)
    grouped = by_match(patterns)
    ent = [p for p in grouped["b.c.example.com."] if "A" in p["types"]][0]
    assert ent["baseline"]["termination"] == "nxdomain"
    assert ent["candidate"]["termination"] == "nodata-ent"


def test_delegation_added():
    cand = BASELINE + "newsub IN NS ns1\n"
    patterns, _, _ = impact(BASELINE, cand)
    grouped = by_match(patterns)
    exact = [p for p in grouped["newsub.example.com."] if "A" in p["types"]][0]
    assert exact["candidate"]["termination"] == "delegation"
    gap = grouped["**.newsub.example.com."]
    assert gap[0]["candidate"]["termination"] == "delegation"
    assert gap[0]["baseline"]["termination"] == "nxdomain"


def test_alias_loop_only_marks_its_pattern():
    cand = BASELINE + "l1 IN CNAME l2\nl2 IN CNAME l1\n"
    patterns, _, _ = impact(BASELINE, cand)
    loop_pats = [p for p in patterns
                 if p["candidate"]["termination"] == "alias-loop"]
    assert loop_pats
    for p in loop_pats:
        assert p["match"] in ("l1.example.com.", "l2.example.com.")


def test_dname_removed():
    cand = BASELINE.replace("d      IN DNAME target\n", "")
    patterns, _, _ = impact(BASELINE, cand)
    grouped = by_match(patterns)
    gap = grouped["**.d.example.com."]
    # baseline rewrites via DNAME (answer carries DNAME+CNAME), candidate
    # is a plain NXDOMAIN: the answers differ even though rcodes match.
    assert gap[0]["baseline"]["rcode"] == "NXDOMAIN"
    assert gap[0]["candidate"]["rcode"] == "NXDOMAIN"
    wit = gap[0]["witness"]
    assert wit["baseline"]["answers"] != wit["candidate"]["answers"]
    assert any("DNAME" in rec for rec in wit["baseline"]["answers"])

def test_patterns_are_mutually_exclusive_and_complete():
    """Property test over a broad sample of in-zone names."""
    cand = CANDIDATE + "*.wild IN A 192.0.2.60\nnewsub IN NS ns1\n"
    patterns, z1, z2 = impact(BASELINE, cand)
    union = z1.exist | z2.exist
    sample = set(union)
    for name in union:
        sample.add(dns.name.from_text("q1", name))
        sample.add(dns.name.from_text("q2.q1", name))
    for name in sample:
        assert name.is_subdomain(ORIGIN)
        for qtype in QUERY_TYPES:
            changed = resolve(z1, name, qtype) != resolve(z2, name, qtype)
            covering = [p for p in patterns if pattern_covers(p, name, qtype)]
            assert len(covering) <= 1, f"overlap at {name}/{qtype}"
            assert (len(covering) == 1) == changed, \
                f"coverage mismatch at {name}/{qtype}: changed={changed}"


def test_witness_answers_match_resolve():
    patterns, z1, z2 = impact(BASELINE, CANDIDATE)
    for p in patterns:
        wit = p["witness"]
        name = dns.name.from_text(wit["name"])
        r1 = resolve(z1, name, wit["type"]).to_dict()
        r2 = resolve(z2, name, wit["type"]).to_dict()
        assert r1 == wit["baseline"]
        assert r2 == wit["candidate"]
        assert r1 != r2
