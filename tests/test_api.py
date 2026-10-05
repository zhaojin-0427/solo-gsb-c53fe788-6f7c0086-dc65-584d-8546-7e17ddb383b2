from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

BASELINE = """
$ORIGIN example.com.
$TTL 300
@      IN SOA ns1 admin 100 7200 3600 1209600 300
@      IN NS  ns1
ns1    IN A   192.0.2.1
www    IN A   192.0.2.10
api    IN CNAME www
"""

CANDIDATE = """
$ORIGIN example.com.
$TTL 300
@      IN SOA ns1 admin 101 7200 3600 1209600 300
@      IN NS  ns1
ns1    IN A   192.0.2.1
www    IN A   192.0.2.99
api    IN CNAME www
"""


def test_index():
    r = client.get("/")
    assert r.status_code == 200
    assert "endpoints" in r.json()


def test_impact_ok():
    r = client.post("/impact", json={
        "origin": "example.com",
        "baseline": BASELINE,
        "candidate": CANDIDATE,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["changed"] is True
    assert body["pattern_count"] == len(body["patterns"]) > 0
    matches = {p["match"] for p in body["patterns"]}
    assert "www.example.com." in matches
    assert "api.example.com." in matches      # CNAME follows the chain
    assert "example.com." in matches          # SOA serial bump
    for p in body["patterns"]:
        assert p["witness"]["baseline"] != p["witness"]["candidate"]


def test_impact_identical():
    r = client.post("/impact", json={
        "origin": "example.com",
        "baseline": BASELINE,
        "candidate": BASELINE,
    })
    assert r.status_code == 200
    assert r.json()["changed"] is False
    assert r.json()["patterns"] == []


def test_impact_invalid_zone_400():
    r = client.post("/impact", json={
        "origin": "example.com",
        "baseline": BASELINE,
        "candidate": CANDIDATE + "bad IN TXT nope\n",
    })
    assert r.status_code == 400
    assert "unsupported record type" in r.json()["detail"]


def test_impact_out_of_zone_400():
    r = client.post("/impact", json={
        "origin": "example.com",
        "baseline": BASELINE,
        "candidate": CANDIDATE + "x.other.com. IN A 192.0.2.1\n",
    })
    assert r.status_code == 400


def test_impact_external_reference_400():
    r = client.post("/impact", json={
        "origin": "example.com",
        "baseline": BASELINE,
        "candidate": CANDIDATE + "ext IN CNAME www.other.com.\n",
    })
    assert r.status_code == 400
    assert "external reference" in r.json()["detail"]


def test_resolve_ok():
    r = client.post("/resolve", json={
        "origin": "example.com",
        "baseline": BASELINE,
        "candidate": CANDIDATE,
        "name": "api.example.com",
        "type": "A",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["changed"] is True
    assert body["baseline"]["answers"] == [
        "api.example.com. 300 IN CNAME www.example.com.",
        "www.example.com. 300 IN A 192.0.2.10",
    ]
    assert body["candidate"]["answers"][-1] == \
        "www.example.com. 300 IN A 192.0.2.99"


def test_resolve_unchanged():
    r = client.post("/resolve", json={
        "origin": "example.com",
        "baseline": BASELINE,
        "candidate": CANDIDATE,
        "name": "ns1.example.com.",
        "type": "A",
    })
    assert r.status_code == 200
    assert r.json()["changed"] is False


def test_resolve_out_of_zone_name_400():
    r = client.post("/resolve", json={
        "origin": "example.com",
        "baseline": BASELINE,
        "candidate": CANDIDATE,
        "name": "www.other.com",
        "type": "A",
    })
    assert r.status_code == 400


def test_resolve_bad_type_400():
    r = client.post("/resolve", json={
        "origin": "example.com",
        "baseline": BASELINE,
        "candidate": CANDIDATE,
        "name": "www.example.com",
        "type": "TXT",
    })
    assert r.status_code == 400


def test_resolve_at_and_relative_names():
    for name in ("@", "example.com.", "example.com"):
        r = client.post("/resolve", json={
            "origin": "example.com",
            "baseline": BASELINE,
            "candidate": CANDIDATE,
            "name": name,
            "type": "SOA",
        })
        assert r.status_code == 200
        assert r.json()["name"] == "example.com."
