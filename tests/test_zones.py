import dns.name
import pytest

from app.zones import ZoneError, parse_origin, parse_zone

ORIGIN = parse_origin("example.com")

BASE = """
$ORIGIN example.com.
$TTL 300
@    IN SOA ns1 admin 1 7200 3600 1209600 300
@    IN NS  ns1
ns1  IN A   192.0.2.1
www  IN A   192.0.2.10
"""


def parse(text):
    return parse_zone(text, ORIGIN)


def test_ok_zone_parses():
    zone = parse(BASE)
    assert zone.origin == ORIGIN
    assert dns.name.from_text("www.example.com.") in zone.exist


def test_relative_and_at_names():
    zone = parse(BASE)
    assert "A" in zone.nodes[dns.name.from_text("www.example.com.")]


def test_out_of_zone_owner_rejected():
    with pytest.raises(ZoneError, match="out-of-zone"):
        parse(BASE + "evil.other.com. IN A 192.0.2.99\n")


def test_external_cname_rejected():
    with pytest.raises(ZoneError, match="external reference"):
        parse(BASE + "alias IN CNAME www.other.com.\n")


def test_external_dname_rejected():
    with pytest.raises(ZoneError, match="external reference"):
        parse(BASE + "d IN DNAME target.other.com.\n")


def test_external_ns_rejected():
    with pytest.raises(ZoneError, match="external reference"):
        parse(BASE + "sub IN NS ns1.other.com.\n")


def test_unsupported_type_rejected():
    with pytest.raises(ZoneError, match="unsupported record type"):
        parse(BASE + "www IN TXT \"hello\"\n")


def test_unsupported_directive_rejected():
    with pytest.raises(ZoneError, match="unsupported master-file directive"):
        parse("$INCLUDE /etc/passwd\n" + BASE)


def test_generate_directive_rejected():
    with pytest.raises(ZoneError, match="unsupported master-file directive"):
        parse(BASE + "$GENERATE 1-9 host$ IN A 192.0.2.$\n")


def test_cname_with_other_data_rejected():
    with pytest.raises(ZoneError, match="CNAME and other data"):
        parse(BASE + "bad IN CNAME www\nbad IN A 192.0.2.5\n")


def test_data_below_dname_rejected():
    with pytest.raises(ZoneError, match="data below DNAME"):
        parse(BASE + "d IN DNAME target\nx.d IN A 192.0.2.6\n")


def test_missing_soa_rejected():
    with pytest.raises(ZoneError, match="no SOA"):
        parse("$ORIGIN example.com.\n$TTL 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n")


def test_garbage_rejected():
    with pytest.raises(ZoneError):
        parse("this is not a zone")


def test_dname_at_delegation_rejected():
    with pytest.raises(ZoneError, match="DNAME at delegation"):
        parse(BASE + "sub IN NS ns1\nsub IN DNAME target\n")


def test_dname_at_apex_allowed():
    zone = parse(
        "$ORIGIN example.com.\n$TTL 300\n"
        "@ IN SOA ns1 admin 1 7200 3600 1209600 300\n"
        "@ IN NS ns1\n@ IN DNAME target\n"
    )
    assert "DNAME" in zone.nodes[ORIGIN]


def test_dname_at_apex_with_data_below_rejected():
    with pytest.raises(ZoneError, match="data below DNAME"):
        parse(BASE + "@ IN DNAME target\n")
