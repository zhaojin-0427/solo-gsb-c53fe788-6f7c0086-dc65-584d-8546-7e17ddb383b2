import dns.name
import pytest

from app.resolver import resolve
from app.zones import parse_origin, parse_zone

ORIGIN = parse_origin("example.com")

ZONE = """
$ORIGIN example.com.
$TTL 300
@      IN SOA ns1 admin 1 7200 3600 1209600 300
@      IN NS  ns1
ns1    IN A   192.0.2.1
www    IN A   192.0.2.10
alias  IN CNAME www
deep.a.b  IN A 192.0.2.20
sub    IN NS  ns1
*.wild IN A  192.0.2.30
d      IN DNAME target
target IN A   192.0.2.40
x.target IN A 192.0.2.41
loop1  IN CNAME loop2
loop2  IN CNAME loop1
"""

zone = parse_zone(ZONE, ORIGIN)


def q(name, qtype):
    return resolve(zone, dns.name.from_text(name, dns.name.root), qtype)


def test_exact_a():
    r = q("www.example.com", "A")
    assert r.rcode == "NOERROR" and r.termination == "exact"
    assert r.answers == ("www.example.com. 300 IN A 192.0.2.10",)


def test_nodata_existing_name_other_types():
    r = q("www.example.com", "AAAA")
    assert (r.rcode, r.termination, r.answers) == ("NOERROR", "nodata", ())


def test_nodata_ent():
    # b.example.com exists only as an empty non-terminal (deep.a.b below)
    r = q("a.b.example.com", "A")
    assert r.termination == "nodata-ent"
    r = q("b.example.com", "A")
    assert r.termination == "nodata-ent"


def test_nxdomain():
    r = q("nope.example.com", "A")
    assert (r.rcode, r.termination) == ("NXDOMAIN", "nxdomain")


def test_delegation_at_cut():
    r = q("sub.example.com", "A")
    assert (r.rcode, r.termination) == ("NOERROR", "delegation")
    assert r.authority == ("sub.example.com. 300 IN NS ns1.example.com.",)


def test_delegation_below_cut():
    r = q("anything.deep.sub.example.com", "AAAA")
    assert r.termination == "delegation"


def test_wildcard_synthesis():
    r = q("xyz.wild.example.com", "A")
    assert r.termination == "wildcard"
    assert r.answers == ("xyz.wild.example.com. 300 IN A 192.0.2.30",)


def test_wildcard_matches_multiple_labels():
    r = q("a.b.c.wild.example.com", "A")
    assert r.termination == "wildcard"
    assert r.answers == ("a.b.c.wild.example.com. 300 IN A 192.0.2.30",)


def test_wildcard_nodata():
    r = q("xyz.wild.example.com", "AAAA")
    assert (r.rcode, r.termination) == ("NOERROR", "nodata-wildcard")


def test_cname_chain():
    r = q("alias.example.com", "A")
    assert r.termination == "exact"
    assert r.answers == (
        "alias.example.com. 300 IN CNAME www.example.com.",
        "www.example.com. 300 IN A 192.0.2.10",
    )


def test_cname_query_for_cname_type_does_not_chase():
    r = q("alias.example.com", "CNAME")
    assert r.termination == "exact"
    assert r.answers == ("alias.example.com. 300 IN CNAME www.example.com.",)


def test_dname_synthesises_cname():
    r = q("x.d.example.com", "A")
    assert r.termination == "exact"
    assert r.answers == (
        "d.example.com. 300 IN DNAME target.example.com.",
        "x.d.example.com. 300 IN CNAME x.target.example.com.",
        "x.target.example.com. 300 IN A 192.0.2.41",
    )


def test_dname_chain_to_nxdomain():
    r = q("missing.d.example.com", "A")
    assert (r.rcode, r.termination) == ("NXDOMAIN", "nxdomain")
    assert r.answers == (
        "d.example.com. 300 IN DNAME target.example.com.",
        "missing.d.example.com. 300 IN CNAME missing.target.example.com.",
    )


def test_dname_does_not_rewrite_owner_itself():
    r = q("d.example.com", "A")
    assert r.termination == "nodata"
    r = q("d.example.com", "DNAME")
    assert r.termination == "exact"


def test_alias_loop():
    r = q("loop1.example.com", "A")
    assert r.termination == "alias-loop"
    assert r.rcode == "NOERROR"


def test_apex_queries():
    assert q("example.com", "SOA").termination == "exact"
    assert q("example.com", "NS").termination == "exact"
    assert q("example.com", "AAAA").termination == "nodata"
