"""HTTP API: POST /impact and POST /resolve."""
from __future__ import annotations

import dns.name
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .impact import compute_impact
from .resolver import resolve
from .zones import QUERY_TYPES, ZoneError, parse_origin, parse_zone

app = FastAPI(
    title="DNS Zone Change Impact API",
    version="1.0.0",
    description=(
        "Compares two versions of a DNS zone (BIND master-file text) and "
        "reports, for every in-zone name and supported type, how the "
        "answers change.  Fully offline: no DNS traffic is ever generated."
    ),
)


class ZonePair(BaseModel):
    origin: str = Field(..., examples=["example.com"])
    baseline: str = Field(..., description="BIND zone text, current version")
    candidate: str = Field(..., description="BIND zone text, new version")


class ResolveRequest(ZonePair):
    name: str = Field(..., examples=["www.example.com"])
    type: str = Field(..., examples=["A"])


def _parse_pair(body: ZonePair):
    try:
        origin = parse_origin(body.origin)
        baseline = parse_zone(body.baseline, origin)
        candidate = parse_zone(body.candidate, origin)
    except ZoneError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return origin, baseline, candidate


@app.get("/")
def index():
    return {
        "service": "DNS Zone Change Impact API",
        "endpoints": {
            "POST /impact": "change patterns between baseline and candidate",
            "POST /resolve": "both versions' answers for one name/type",
        },
        "query_types": QUERY_TYPES,
    }


@app.post("/impact")
def impact(body: ZonePair):
    origin, baseline, candidate = _parse_pair(body)
    patterns = compute_impact(baseline, candidate)
    return {
        "origin": str(origin).lower(),
        "changed": bool(patterns),
        "pattern_count": len(patterns),
        "patterns": patterns,
    }


@app.post("/resolve")
def resolve_query(body: ResolveRequest):
    origin, baseline, candidate = _parse_pair(body)
    qtype = body.type.upper()
    if qtype not in QUERY_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"unsupported query type {body.type!r}; "
                   f"supported: {', '.join(QUERY_TYPES)}",
        )
    try:
        if body.name.strip() == "@":
            qname = origin
        else:
            # names are absolute; a missing trailing dot is tolerated
            qname = dns.name.from_text(body.name.strip(), dns.name.root)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400, detail=f"invalid query name: {exc}"
        ) from exc
    if not qname.is_subdomain(origin):
        raise HTTPException(
            status_code=400,
            detail=f"query name {qname} is outside the zone "
                   f"(no out-of-zone resolution is performed)",
        )
    r1 = resolve(baseline, qname, qtype)
    r2 = resolve(candidate, qname, qtype)
    return {
        "name": str(qname).lower(),
        "type": qtype,
        "changed": r1 != r2,
        "baseline": r1.to_dict(),
        "candidate": r2.to_dict(),
    }
