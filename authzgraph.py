#!/usr/bin/env python3
"""authzgraph — object-graph authorization fuzzer for IDOR / BOLA bugs.

Single-file build. All stages (ingest -> id-detect -> object graph -> planner ->
executor -> diff -> report) plus the self-contained demo (mock target, capture
generator) and the offline tests live in this one file.

    ingest      parse HAR, attribute each request to an actor by its auth
    id-detect   classify values as uuid/int/mongo/jwt/hashid; infer object type
    graph       normalize endpoints to templates; build produce/consume edges;
                correlate a type across versions & protocols
    planner     find victim-owned objects; plan cross-tenant / cross-role /
                unauth probes over every consuming endpoint
    executor    clone an exemplar, swap the victim id + attacker session;
                scope-gated, rate-limited, DRY-RUN BY DEFAULT
    diff        VULNERABLE / NOT_VULNERABLE / REVIEW via victim markers +
                similarity to victim vs. forbidden baselines
    report      console / JSON / markdown

----------------------------------------------------------------------------
 AUTHORIZED USE ONLY. `run --live` sends real cross-account requests. Only run
 it against systems you own or a program that has EXPLICITLY authorized you,
 and stay inside the declared scope. The scope allowlist and dry-run default
 are guard rails, not permission. The responsibility is yours.
----------------------------------------------------------------------------

Quick start (one file, no other files needed):

    python authzgraph.py demo-server &                 # mock vulnerable target
    python authzgraph.py demo-capture capture.har      # legit traffic -> HAR
    python authzgraph.py demo-config config.yaml       # example actors YAML
    python authzgraph.py analyze --config config.yaml --har capture.har
    python authzgraph.py run --config config.yaml --har capture.har \
        --scope 127.0.0.1 --live --rate 5 --markdown findings.md
    python authzgraph.py selftest                       # offline decision tests

License: MIT. Provided for authorized security testing and education.
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from typing import Any, Iterator, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


# ===========================================================================
# models — core data structures shared across the pipeline
# ===========================================================================

@dataclass
class Actor:
    """An identity the tool can act as. Traffic is attributed to an actor by
    matching its auth material (a header value or cookie) against `match`."""
    name: str
    tenant: Optional[str] = None       # tenant/org the actor belongs to
    role: Optional[str] = None         # e.g. "admin", "member", "viewer"
    # Auth material used both to ATTRIBUTE captured traffic to this actor and
    # to IMPERSONATE this actor when replaying. e.g.
    #   {"header": {"Authorization": "Bearer eyJ..."}}
    #   {"cookie": {"session": "abc123"}}
    auth: dict[str, dict[str, str]] = field(default_factory=dict)
    # Substrings that identify this actor in a captured request when auth
    # material isn't a clean match (optional, advanced).
    match: list[str] = field(default_factory=list)

    def auth_headers(self) -> dict[str, str]:
        headers = dict(self.auth.get("header", {}))
        cookies = self.auth.get("cookie", {})
        if cookies:
            jar = "; ".join(f"{k}={v}" for k, v in cookies.items())
            existing = headers.get("Cookie")
            headers["Cookie"] = f"{existing}; {jar}" if existing else jar
        return headers

    def credential_fingerprints(self) -> list[str]:
        """Strings that, if present in a request, mark it as this actor's."""
        fps = list(self.match)
        for v in self.auth.get("header", {}).values():
            fps.append(v)
        for k, v in self.auth.get("cookie", {}).items():
            fps.append(f"{k}={v}")
        return [f for f in fps if f]


@dataclass
class HttpRecord:
    """A single captured request/response pair, attributed to an actor."""
    actor: Optional[str]
    method: str
    url: str
    host: str
    path: str
    query: dict[str, list[str]] = field(default_factory=dict)
    req_headers: dict[str, str] = field(default_factory=dict)
    req_body: Optional[str] = None
    status: int = 0
    resp_headers: dict[str, str] = field(default_factory=dict)
    resp_body: Optional[str] = None
    # Protocol flavor: "rest" or "graphql"
    protocol: str = "rest"
    # For GraphQL: operation name and parsed variables
    gql_operation: Optional[str] = None
    gql_variables: dict[str, Any] = field(default_factory=dict)


@dataclass
class ObjectRef:
    """A concrete identifier value observed in traffic, tied to a type."""
    value: str
    type_name: str
    id_format: str          # uuid | int | mongo | hashid | jwt | opaque
    field_name: Optional[str] = None


@dataclass
class EndpointTemplate:
    """A normalized endpoint, with ID-bearing segments replaced by {id}."""
    method: str
    host: str
    template: str           # e.g. /api/v1/orders/{id}
    protocol: str = "rest"
    gql_operation: Optional[str] = None
    # object types this endpoint RETURNS in responses
    produces: set[str] = field(default_factory=set)
    # object types this endpoint ACCEPTS as path/query/body params
    consumes: set[str] = field(default_factory=set)
    # concrete records that matched this template (exemplars for replay)
    exemplars: list[HttpRecord] = field(default_factory=list)

    @property
    def key(self) -> str:
        op = f"#{self.gql_operation}" if self.gql_operation else ""
        return f"{self.method} {self.host}{self.template}{op}"


@dataclass
class ObjectType:
    """A logical object type and everything we learned about it."""
    name: str
    id_format: str = "opaque"
    # all id values seen, mapped to the set of actors that touched them
    instances: dict[str, set[str]] = field(default_factory=dict)
    producers: set[str] = field(default_factory=set)   # endpoint keys
    consumers: set[str] = field(default_factory=set)    # endpoint keys

    def owners(self, value: str) -> set[str]:
        return self.instances.get(value, set())


@dataclass
class TestCase:
    """A planned authorization probe."""
    object_type: str
    victim_id: str
    victim_actor: str
    attacker_actor: str
    attack_kind: str             # "cross-tenant" | "cross-role" | "unauth"
    endpoint_key: str
    exemplar: HttpRecord         # request to clone and mutate
    # the concrete substitution we will perform
    substitutions: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    verdict: str                 # VULNERABLE | NOT_VULNERABLE | REVIEW | ERROR
    confidence: float            # 0.0 - 1.0
    test: TestCase
    observed_status: int = 0
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


# ===========================================================================
# iddetect — identify identifier-like values and learn their formats
# ===========================================================================
# This is what lets the tool reason about *objects* rather than raw strings:
# it decides which values in a request/response are object IDs, what format
# they take, and (via field/path context) what type of object they name.

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
MONGO_RE = re.compile(r"^[0-9a-f]{24}$", re.I)
JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
INT_RE = re.compile(r"^\d{1,19}$")
HASHID_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")

# Field names that strongly suggest the value is an identifier.
ID_NAME_RE = re.compile(r"(^|_)(id|uuid|guid|ref|key|sid|pid|oid|slug)$", re.I)
# GraphQL global ids are often base64 of "Type:123"
GQL_GLOBAL_RE = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")


def id_format(value: str) -> Optional[str]:
    """Return a format label if `value` looks like an identifier, else None."""
    if not isinstance(value, str) or not value:
        return None
    if UUID_RE.match(value):
        return "uuid"
    if MONGO_RE.match(value):
        return "mongo"
    if JWT_RE.match(value):
        return "jwt"
    if INT_RE.match(value):
        # pure ints are only interesting as IDs in context; caller gates this
        return "int"
    if HASHID_RE.match(value) and any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
        return "hashid"
    return None


def looks_like_id(name: Optional[str], value: Any) -> Optional[str]:
    """Decide if (field_name, value) is an identifier. Returns format or None.

    A bare integer is accepted only when the field name signals an ID, to avoid
    treating prices, counts, quantities, etc. as object identifiers.
    """
    if not isinstance(value, (str, int)):
        return None
    sval = str(value)
    fmt = id_format(sval)
    named = bool(name and ID_NAME_RE.search(name))
    if fmt == "int":
        return "int" if named else None
    if fmt == "hashid":
        # hashids are ambiguous (any alphanumeric slug); only trust them in an
        # id-named field, to avoid typing notes/descriptions/tokens as objects.
        return "hashid" if named else None
    if fmt:
        return fmt
    # opaque: a named id field whose value we couldn't classify
    if named and 0 < len(sval) <= 128:
        return "opaque"
    return None


def type_from_field(name: str) -> str:
    """order_id -> order, userUuid -> user, id -> <object>."""
    base = re.sub(r"(_|)(id|uuid|guid|ref|key)$", "", name, flags=re.I)
    base = base.strip("_") or "object"
    return singularize(base.lower())


def type_from_path_segment(segment: str) -> str:
    return singularize(segment.lower().strip("/"))


def singularize(word: str) -> str:
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith("ses") or word.endswith("xes") or word.endswith("zes"):
        return word[:-2]
    if word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def walk_json(obj: Any, path: str = "") -> Iterator[tuple[str, str, Any]]:
    """Yield (parent_field, leaf_field, value) for every scalar in a JSON tree."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                yield from walk_json(v, k)
            else:
                yield (path, k, v)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_json(item, path)


def extract_ids_from_json(text: Optional[str]) -> list[tuple[str, str, str, str]]:
    """Return list of (type_name, id_value, id_format, field_name) from a JSON body.

    Uses __typename when present to type-stamp sibling ids (GraphQL-aware)."""
    out: list[tuple[str, str, str, str]] = []
    if not text:
        return out
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return out

    def visit(node: Any, context_type: Optional[str]):
        if isinstance(node, dict):
            ctype = node.get("__typename") or context_type
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    visit(v, ctype)
                else:
                    fmt = looks_like_id(k, v)
                    if fmt:
                        if k.lower() in ("id", "_id") and ctype:
                            tname = singularize(str(ctype).lower())
                        else:
                            tname = type_from_field(k)
                        out.append((tname, str(v), fmt, k))
        elif isinstance(node, list):
            for item in node:
                visit(item, context_type)

    visit(data, None)
    return out


# ===========================================================================
# ingest — turn captured traffic (HAR) into actor-attributed HttpRecords
# ===========================================================================
# HAR is the pragmatic input: Burp, mitmproxy, and every browser export it, so
# a hunter already has it. Mobile-API traffic (older/internal API versions
# surfaced by decompiling an APK) correlates automatically once it's captured.

def _headers_to_dict(entries: list[dict]) -> dict[str, str]:
    return {h.get("name", ""): h.get("value", "") for h in entries if h.get("name")}


def _attribute_actor(req_headers: dict[str, str], body: Optional[str],
                     actors: list[Actor]) -> Optional[str]:
    """Match a request to the actor whose credential it carries."""
    blob = "\n".join(f"{k}: {v}" for k, v in req_headers.items())
    if body:
        blob += "\n" + body
    for actor in actors:
        for fp in actor.credential_fingerprints():
            if fp and fp in blob:
                return actor.name
    return None


def _parse_graphql(method: str, body: Optional[str], resp_body: Optional[str]):
    """Return (is_graphql, operation_name, variables)."""
    if not body:
        return False, None, {}
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return False, None, {}
    if isinstance(payload, dict) and ("query" in payload or "mutation" in payload):
        op = payload.get("operationName")
        if not op and isinstance(payload.get("query"), str):
            q = payload["query"].strip()
            # crude: grab the operation name after query/mutation keyword
            for kw in ("query", "mutation"):
                if q.startswith(kw):
                    rest = q[len(kw):].strip()
                    op = rest.split("(")[0].split("{")[0].strip() or None
                    break
        return True, op, payload.get("variables") or {}
    return False, None, {}


def load_har(path: str, actors: list[Actor]) -> list[HttpRecord]:
    with open(path, "r", encoding="utf-8") as fh:
        har = json.load(fh)
    entries = har.get("log", {}).get("entries", [])
    records: list[HttpRecord] = []
    for e in entries:
        req = e.get("request", {})
        resp = e.get("response", {})
        url = req.get("url", "")
        if not url:
            continue
        parsed = urlparse(url)
        req_headers = _headers_to_dict(req.get("headers", []))
        resp_headers = _headers_to_dict(resp.get("headers", []))
        body = (req.get("postData") or {}).get("text")
        resp_body = (resp.get("content") or {}).get("text")
        is_gql, op, variables = _parse_graphql(req.get("method", "GET"), body, resp_body)

        rec = HttpRecord(
            actor=_attribute_actor(req_headers, body, actors),
            method=req.get("method", "GET").upper(),
            url=url,
            host=parsed.netloc,
            path=parsed.path or "/",
            query=parse_qs(parsed.query),
            req_headers=req_headers,
            req_body=body,
            status=resp.get("status", 0),
            resp_headers=resp_headers,
            resp_body=resp_body,
            protocol="graphql" if is_gql else "rest",
            gql_operation=op,
            gql_variables=variables,
        )
        records.append(rec)
    return records


# ===========================================================================
# graph — build the object graph from captured records
# ===========================================================================
# Nodes: object types. Edges: endpoints that PRODUCE a type (return its ids)
# and endpoints that CONSUME a type (take its ids as input). Correlation groups
# every path to the same object type across REST paths, GraphQL operations, and
# API versions, which is what turns replay into reasoning.

VERSION_RE = re.compile(r"^v\d+$|^v\d+\.\d+$|^internal$|^beta$|^legacy$", re.I)


class ObjectModel:
    def __init__(self) -> None:
        self.types: dict[str, ObjectType] = {}
        self.endpoints: dict[str, EndpointTemplate] = {}

    # ---- type bookkeeping -------------------------------------------------
    def _type(self, name: str, fmt: str) -> ObjectType:
        t = self.types.get(name)
        if not t:
            t = ObjectType(name=name, id_format=fmt)
            self.types[name] = t
        elif t.id_format == "opaque" and fmt != "opaque":
            t.id_format = fmt
        return t

    def _record_instance(self, type_name: str, fmt: str, value: str, actor: Optional[str]):
        t = self._type(type_name, fmt)
        owners = t.instances.setdefault(value, set())
        if actor:
            owners.add(actor)

    # ---- template normalization ------------------------------------------
    def _templatize(self, rec: HttpRecord) -> tuple[str, list[tuple[str, str, str]]]:
        """Replace id-bearing path segments with {id}. Return (template, consumed).
        consumed = list of (type_name, id_value, id_format)."""
        segments = [s for s in rec.path.split("/") if s != ""]
        out_segments: list[str] = []
        consumed: list[tuple[str, str, str]] = []
        prev_type_hint: Optional[str] = None
        for seg in segments:
            fmt = id_format(seg)
            # treat pure ints as ids in a path only when a resource name precedes
            is_id = fmt is not None and (fmt != "int" or prev_type_hint is not None)
            if is_id:
                tname = prev_type_hint or "object"
                out_segments.append("{id}")
                consumed.append((tname, seg, fmt))
            else:
                out_segments.append(seg)
                if not VERSION_RE.match(seg):
                    prev_type_hint = type_from_path_segment(seg)
        template = "/" + "/".join(out_segments)

        # query-string ids
        for k, vals in rec.query.items():
            for v in vals:
                fmt = looks_like_id(k, v)
                if fmt:
                    consumed.append((type_from_field(k), v, fmt))

        # body ids (REST json or graphql variables)
        if rec.protocol == "graphql":
            for k, v in _flatten(rec.gql_variables):
                fmt = looks_like_id(k, v)
                if fmt:
                    consumed.append((type_from_field(k), str(v), fmt))
        elif rec.req_body:
            try:
                data = json.loads(rec.req_body)
                for parent, leaf, v in walk_json(data):
                    fmt = looks_like_id(leaf, v)
                    if fmt:
                        consumed.append((type_from_field(leaf), str(v), fmt))
            except (ValueError, TypeError):
                pass
        return template, consumed

    def _normalize_template(self, template: str) -> str:
        """Collapse version markers so /v1/orders/{id} ~ /v2/orders/{id}."""
        parts = [p for p in template.split("/") if p]
        parts = ["{ver}" if VERSION_RE.match(p) else p for p in parts]
        return "/" + "/".join(parts)

    # ---- public build -----------------------------------------------------
    def ingest(self, records: list[HttpRecord]) -> None:
        for rec in records:
            template, consumed = self._templatize(rec)
            ep = EndpointTemplate(
                method=rec.method, host=rec.host, template=template,
                protocol=rec.protocol, gql_operation=rec.gql_operation,
            )
            ep = self.endpoints.setdefault(ep.key, ep)
            ep.exemplars.append(rec)

            for tname, value, fmt in consumed:
                ep.consumes.add(tname)
                self._record_instance(tname, fmt, value, rec.actor)
                self._type(tname, fmt).consumers.add(ep.key)

            # produced ids: anything id-like in a 2xx response body
            if 200 <= rec.status < 300 and rec.resp_body:
                for tname, value, fmt, fname in extract_ids_from_json(rec.resp_body):
                    ep.produces.add(tname)
                    self._record_instance(tname, fmt, value, rec.actor)
                    self._type(tname, fmt).producers.add(ep.key)

    # ---- correlation ------------------------------------------------------
    def correlate(self) -> dict[str, list[str]]:
        """Map each object type to every endpoint key that touches it,
        grouped across versions and protocols."""
        paths_to_type: dict[str, list[str]] = {}
        for tname, t in self.types.items():
            keys = sorted(t.producers | t.consumers)
            paths_to_type[tname] = keys
        return paths_to_type

    def endpoints_consuming(self, type_name: str) -> list[EndpointTemplate]:
        t = self.types.get(type_name)
        if not t:
            return []
        return [self.endpoints[k] for k in t.consumers if k in self.endpoints]


def _flatten(obj, parent: str = ""):
    """Yield (key, value) scalar pairs from nested dict/list (for gql vars)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                yield from _flatten(v, k)
            else:
                yield (k, v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _flatten(item, parent)


# ===========================================================================
# planner — turn the object graph into concrete authorization probes
# ===========================================================================
# For every object that appears to belong to a victim actor, find every
# endpoint that consumes that object type and plan a request where a *different*
# actor (different tenant, or lower role, or no auth) tries to reach it.

def _owned_only_by(model: ObjectModel, type_name: str, value: str) -> Optional[str]:
    """If exactly one actor ever touched this id, return that actor (the owner)."""
    owners = model.types[type_name].owners(value)
    named = {o for o in owners if o}
    return next(iter(named)) if len(named) == 1 else None


def _pick_exemplar(ep, attacker: Actor) -> Optional[HttpRecord]:
    """Prefer a request the attacker actually made (valid structure for them),
    else any exemplar to clone."""
    for rec in ep.exemplars:
        if rec.actor == attacker.name:
            return rec
    return ep.exemplars[0] if ep.exemplars else None


def _relationship(victim: Actor, attacker: Actor) -> Optional[str]:
    if attacker.name == victim.name:
        return None
    if victim.tenant and attacker.tenant and victim.tenant != attacker.tenant:
        return "cross-tenant"
    if victim.role and attacker.role and victim.role != attacker.role:
        return "cross-role"
    if attacker.tenant == victim.tenant:
        return "cross-role"   # same tenant, probe lateral access anyway
    return "cross-tenant"


def plan(model: ObjectModel, actors: list[Actor],
         include_unauth: bool = True, max_per_type: int = 25) -> list[TestCase]:
    by_name = {a.name: a for a in actors}
    cases: list[TestCase] = []

    for type_name, otype in model.types.items():
        consuming = model.endpoints_consuming(type_name)
        if not consuming:
            continue
        planned_for_type = 0
        for value, owners in otype.instances.items():
            if planned_for_type >= max_per_type:
                break
            owner_name = _owned_only_by(model, type_name, value)
            if not owner_name or owner_name not in by_name:
                continue
            victim = by_name[owner_name]

            for ep in consuming:
                # attackers = every other configured actor
                attackers = [a for a in actors if a.name != victim.name]
                if include_unauth:
                    attackers = attackers + [Actor(name="__unauth__")]
                for attacker in attackers:
                    kind = ("unauth" if attacker.name == "__unauth__"
                            else _relationship(victim, attacker))
                    if not kind:
                        continue
                    exemplar = _pick_exemplar(ep, attacker if attacker.name != "__unauth__"
                                              else victim)
                    if not exemplar:
                        continue
                    case = TestCase(
                        object_type=type_name,
                        victim_id=value,
                        victim_actor=victim.name,
                        attacker_actor=attacker.name,
                        attack_kind=kind,
                        endpoint_key=ep.key,
                        exemplar=copy.deepcopy(exemplar),
                        substitutions={"victim_id": value},
                    )
                    cases.append(case)
                    planned_for_type += 1
    return cases


# ===========================================================================
# executor — build and (optionally) send the mutated authorization probe
# ===========================================================================
# Safety rails, by design:
#   * dry-run is the DEFAULT: nothing leaves the machine unless you pass live=True
#   * every request is checked against an explicit in-scope host allowlist
#   * requests are rate-limited
# Only run live against assets you own or a program that has authorized you.

class ScopeError(Exception):
    pass


@dataclass
class ExecConfig:
    live: bool = False
    scope_hosts: list[str] = field(default_factory=list)
    rate_per_sec: float = 1.0
    timeout: float = 15.0
    strip_headers: tuple[str, ...] = ("content-length", "host")


@dataclass
class ExecResult:
    sent: bool
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    planned_request: dict = field(default_factory=dict)
    error: Optional[str] = None


def _host_in_scope(host: str, scope: list[str]) -> bool:
    host = host.split(":")[0].lower()
    for s in scope:
        s = s.lower().lstrip("*.")
        if host == s or host.endswith("." + s):
            return True
    return False


def _swap_value(text: str, old: str, new: str) -> str:
    return text.replace(old, new) if old and old != new else text


def _mutate_url(url: str, victim_id: str, decoy_id: Optional[str]) -> str:
    """Put the victim id wherever the exemplar had the attacker's own id."""
    parsed = urlparse(url)
    path = parsed.path
    query = parse_qs(parsed.query)
    if decoy_id:
        path = _swap_value(path, decoy_id, victim_id)
        query = {k: [_swap_value(v, decoy_id, victim_id) for v in vals]
                 for k, vals in query.items()}
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(path=path, query=new_query))


def _attacker_own_id(exemplar: HttpRecord, object_type: str) -> Optional[str]:
    """Best-effort: the id the attacker used for this object type in the exemplar,
    so we know what to replace with the victim id."""
    # look in path segments
    for seg in exemplar.path.split("/"):
        if seg and seg.lower() != object_type and any(c.isdigit() for c in seg):
            # candidate id-ish segment
            if id_format(seg):
                return seg
    # look in query
    for vals in exemplar.query.values():
        for v in vals:
            if id_format(v):
                return v
    return None


def build_request(case: TestCase, actors: dict[str, Actor]) -> dict:
    """Return a concrete request dict for the probe (no sending)."""
    ex = case.exemplar
    decoy = _attacker_own_id(ex, case.object_type)
    url = _mutate_url(ex.url, case.victim_id, decoy)

    headers = {k: v for k, v in ex.req_headers.items()
               if k.lower() not in ("authorization", "cookie", "content-length", "host")}
    if case.attacker_actor != "__unauth__":
        attacker = actors[case.attacker_actor]
        headers.update(attacker.auth_headers())

    body = ex.req_body
    if body and decoy:
        body = _swap_value(body, decoy, case.victim_id)

    return {
        "method": ex.method,
        "url": url,
        "headers": headers,
        "body": body,
        "decoy_id_replaced": decoy,
    }


def execute(case: TestCase, actors: dict[str, Actor], cfg: ExecConfig) -> ExecResult:
    planned = build_request(case, actors)
    host = urlparse(planned["url"]).netloc
    if not _host_in_scope(host, cfg.scope_hosts):
        return ExecResult(sent=False, planned_request=planned,
                          error=f"host {host!r} not in scope allowlist")
    if not cfg.live:
        return ExecResult(sent=False, planned_request=planned)

    import requests
    time.sleep(1.0 / cfg.rate_per_sec if cfg.rate_per_sec > 0 else 0)
    try:
        resp = requests.request(
            planned["method"], planned["url"],
            headers=planned["headers"], data=planned["body"],
            timeout=cfg.timeout, allow_redirects=False,
        )
        return ExecResult(
            sent=True, status=resp.status_code,
            headers=dict(resp.headers), body=resp.text,
            planned_request=planned,
        )
    except Exception as exc:  # noqa: BLE001 - surface any transport error
        return ExecResult(sent=False, planned_request=planned, error=str(exc))


# ===========================================================================
# diff — decide whether a probe actually exposed the victim's object
# ===========================================================================
# A 2xx alone means nothing: apps return 200 with empty results constantly. The
# discriminating question is "did the attacker get back data that is uniquely
# the VICTIM's?" We answer it by comparing the observed response to two
# baselines and checking for victim-specific markers, to keep false positives
# down.

VOLATILE_KEYS = re.compile(r"(timestamp|time|date|csrf|nonce|request[_-]?id|trace|etag|expires|updated|created)", re.I)
TOKEN_RE = re.compile(r"[A-Za-z0-9_@.:/-]{2,}")


def _canonical(body: Optional[str]) -> str:
    if not body:
        return ""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return body.strip()

    def scrub(node):
        if isinstance(node, dict):
            return {k: scrub(v) for k, v in sorted(node.items())
                    if not VOLATILE_KEYS.search(k)}
        if isinstance(node, list):
            return [scrub(x) for x in node]
        return node

    return json.dumps(scrub(data), sort_keys=True, separators=(",", ":"))


def _tokens(body: Optional[str]) -> set[str]:
    return set(TOKEN_RE.findall(_canonical(body)))


def _similarity(a: Optional[str], b: Optional[str]) -> float:
    ca, cb = _canonical(a), _canonical(b)
    if not ca and not cb:
        return 1.0
    if not ca or not cb:
        return 0.0
    ta, tb = _tokens(a), _tokens(b)
    if ta and tb:
        jac = len(ta & tb) / len(ta | tb)
    else:
        jac = 0.0
    seq = SequenceMatcher(None, ca, cb).ratio()
    return max(jac, seq)


def _victim_markers(victim_legit: Optional[str], victim_id: str) -> set[str]:
    """Distinctive tokens that should only appear if the VICTIM's object leaked."""
    markers = {victim_id} if victim_id else set()
    if victim_legit:
        toks = _tokens(victim_legit)
        # keep id-ish / high-entropy tokens; drop common words
        for t in toks:
            if len(t) >= 8 and any(c.isdigit() for c in t):
                markers.add(t)
            elif re.match(r"^[0-9a-f-]{16,}$", t, re.I):
                markers.add(t)
    return {m for m in markers if m}


def _is_empty_or_error(body: Optional[str]) -> bool:
    c = _canonical(body)
    if not c or c in ("{}", "[]", "null", '{"data":null}'):
        return True
    low = c.lower()
    return any(w in low for w in ('"error"', "forbidden", "unauthorized",
                                  "not found", "access denied", "permission"))


def evaluate(case: TestCase, observed_status: int, observed_body: Optional[str],
             victim_legit: Optional[str] = None,
             forbidden_baseline: Optional[str] = None) -> Finding:
    reasons: list[str] = []
    markers = _victim_markers(victim_legit, case.victim_id)
    obs_tokens = _tokens(observed_body)
    marker_hits = sorted(markers & obs_tokens)
    sim_victim = _similarity(observed_body, victim_legit) if victim_legit else None
    sim_forbidden = _similarity(observed_body, forbidden_baseline) if forbidden_baseline else None

    evidence = {
        "observed_status": observed_status,
        "marker_hits": marker_hits[:10],
        "similarity_to_victim": round(sim_victim, 3) if sim_victim is not None else None,
        "similarity_to_forbidden": round(sim_forbidden, 3) if sim_forbidden is not None else None,
        "observed_snippet": (observed_body or "")[:400],
    }

    # --- correctly denied -------------------------------------------------
    if observed_status in (401, 403):
        reasons.append(f"server denied access with {observed_status}")
        return Finding("NOT_VULNERABLE", 0.95, case, observed_status, reasons, evidence)

    if observed_status == 404:
        if marker_hits:
            reasons.append("404 but victim markers present in body — object-hiding bypass?")
            return Finding("REVIEW", 0.5, case, observed_status, reasons, evidence)
        reasons.append("object not found / not exposed")
        return Finding("NOT_VULNERABLE", 0.8, case, observed_status, reasons, evidence)

    if observed_status >= 500:
        reasons.append(f"server error {observed_status} — inconclusive")
        return Finding("REVIEW", 0.3, case, observed_status, reasons, evidence)

    # --- 2xx: the interesting case ---------------------------------------
    if 200 <= observed_status < 300:
        if sim_forbidden is not None and sim_forbidden >= 0.95 and not marker_hits:
            reasons.append("response matches the known forbidden/empty baseline")
            return Finding("NOT_VULNERABLE", 0.85, case, observed_status, reasons, evidence)

        if marker_hits and sim_victim is not None and sim_victim >= 0.7:
            reasons.append(f"2xx and response closely matches victim's own data "
                           f"(sim={sim_victim:.2f}) and contains victim markers {marker_hits[:3]}")
            return Finding("VULNERABLE", 0.95, case, observed_status, reasons, evidence)

        if case.victim_id in (observed_body or "") and not _is_empty_or_error(observed_body):
            reasons.append("2xx and the victim's object id is echoed in a non-empty response")
            return Finding("VULNERABLE", 0.8, case, observed_status, reasons, evidence)

        if marker_hits:
            reasons.append(f"2xx with victim markers present {marker_hits[:3]} but weak overall match")
            return Finding("REVIEW", 0.6, case, observed_status, reasons, evidence)

        if _is_empty_or_error(observed_body):
            reasons.append("2xx but body is empty/error-shaped — likely filtered server-side")
            return Finding("NOT_VULNERABLE", 0.7, case, observed_status, reasons, evidence)

        reasons.append("2xx with no victim markers — needs a human look")
        return Finding("REVIEW", 0.4, case, observed_status, reasons, evidence)

    reasons.append(f"unhandled status {observed_status}")
    return Finding("REVIEW", 0.3, case, observed_status, reasons, evidence)


# ===========================================================================
# report — render graph summaries and findings for humans and for reports
# ===========================================================================

VERDICT_ORDER = {"VULNERABLE": 0, "REVIEW": 1, "ERROR": 2, "NOT_VULNERABLE": 3}


def graph_summary(model: ObjectModel) -> str:
    lines = ["# Object graph", ""]
    lines.append(f"{len(model.types)} object types, {len(model.endpoints)} endpoints\n")
    for name, t in sorted(model.types.items()):
        lines.append(f"- {name}  [{t.id_format}]  "
                     f"{len(t.instances)} ids, "
                     f"{len(t.producers)} producer(s), {len(t.consumers)} consumer(s)")
        protocols = {model.endpoints[k].protocol for k in (t.producers | t.consumers)
                     if k in model.endpoints}
        if len(protocols) > 1 or "graphql" in protocols:
            lines.append(f"    reachable via: {', '.join(sorted(protocols))}")
    return "\n".join(lines)


def findings_console(findings: list[Finding]) -> str:
    findings = sorted(findings, key=lambda f: (VERDICT_ORDER.get(f.verdict, 9), -f.confidence))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    out = ["", "=" * 70, "RESULTS: " + "  ".join(f"{k}={v}" for k, v in counts.items()),
           "=" * 70]
    for f in findings:
        t = f.test
        out.append(f"\n[{f.verdict}] conf={f.confidence:.2f}  {t.attack_kind}")
        out.append(f"    endpoint : {t.endpoint_key}")
        out.append(f"    object   : {t.object_type} id={t.victim_id} "
                   f"(victim={t.victim_actor}, as={t.attacker_actor})")
        out.append(f"    status   : {f.observed_status}")
        for r in f.reasons:
            out.append(f"    why      : {r}")
    return "\n".join(out)


def findings_json(findings: list[Finding]) -> str:
    def enc(f: Finding):
        d = asdict(f)
        d["test"].pop("exemplar", None)  # drop heavy raw record
        return d
    return json.dumps([enc(f) for f in findings], indent=2)


def findings_markdown(findings: list[Finding]) -> str:
    vulns = [f for f in findings if f.verdict == "VULNERABLE"]
    lines = ["# Authorization findings", ""]
    if not vulns:
        lines.append("_No high-confidence authorization bypasses found. "
                     "See REVIEW items for manual follow-up._")
    for i, f in enumerate(vulns, 1):
        t = f.test
        lines += [
            f"## {i}. {t.attack_kind.title()} access to `{t.object_type}`",
            "",
            f"**Endpoint:** `{t.endpoint_key}`  ",
            f"**Confidence:** {f.confidence:.2f}  ",
            f"**Impact:** actor `{t.attacker_actor}` accessed `{t.object_type}` "
            f"`{t.victim_id}` owned by `{t.victim_actor}`.",
            "",
            "**Evidence:**",
            "",
            "```",
            *[f"- {r}" for r in f.reasons],
            f"- observed status: {f.observed_status}",
            f"- victim markers echoed: {f.evidence.get('marker_hits')}",
            "```",
            "",
        ]
    return "\n".join(lines)


# ===========================================================================
# pipeline — wire the stages: ingest -> graph -> plan -> execute -> evaluate
# ===========================================================================

def _records(model: ObjectModel) -> list[HttpRecord]:
    seen: list[HttpRecord] = []
    for ep in model.endpoints.values():
        seen.extend(ep.exemplars)
    return seen


def _victim_legit(model: ObjectModel, case: TestCase) -> Optional[str]:
    """The victim's own successful response that reveals this object's data."""
    best = None
    for rec in _records(model):
        if rec.actor != case.victim_actor:
            continue
        if not (200 <= rec.status < 300) or not rec.resp_body:
            continue
        if case.victim_id in (rec.resp_body or "") or case.victim_id in rec.url:
            # prefer the same endpoint template
            if rec.method == case.exemplar.method and case.object_type in rec.path.lower():
                return rec.resp_body
            best = best or rec.resp_body
    return best


def _forbidden_baseline(model: ObjectModel, case: TestCase) -> Optional[str]:
    """A denied/empty response shape for the attacker on this kind of endpoint."""
    for rec in _records(model):
        if rec.actor != case.attacker_actor:
            continue
        if rec.status in (401, 403, 404) and rec.resp_body:
            if case.object_type in rec.path.lower():
                return rec.resp_body
    return None


def run(model: ObjectModel, cases: list[TestCase], actors: list[Actor],
        cfg: ExecConfig) -> list[Finding]:
    by_name = {a.name: a for a in actors}
    findings: list[Finding] = []
    for case in cases:
        result = execute(case, by_name, cfg)
        if not result.sent:
            # dry-run or out-of-scope: record as a planned, unexecuted probe
            verdict = "REVIEW" if cfg.live else "PLANNED"
            reason = result.error or "dry-run: not sent"
            findings.append(Finding(verdict, 0.0, case, 0, [reason],
                                    {"planned_request": result.planned_request}))
            continue
        victim_legit = _victim_legit(model, case)
        forbidden = _forbidden_baseline(model, case)
        findings.append(evaluate(case, result.status, result.body,
                                 victim_legit, forbidden))
    return findings


# ===========================================================================
# demo — self-contained vulnerable target + legit-traffic capture generator
# ===========================================================================
# A tiny, deliberately-vulnerable target for exercising authzgraph locally.
#   /api/v1/orders/<id>   -> VULNERABLE: returns any order to any logged-in user
#   /api/v2/orders/<id>   -> FIXED: 403 unless the order belongs to your tenant
# Two users across two tenants. FOR LOCAL TESTING ONLY.

_DEMO_USERS = {
    "token-alice": {"user": "alice", "tenant": "t1"},
    "token-bob":   {"user": "bob",   "tenant": "t2"},
}
_DEMO_ORDERS = {
    "1001": {"order_id": "1001", "tenant": "t1", "owner": "alice",
             "total": 42.50, "secret_note": "alice-private-A1B2C3D4E5F6"},
    "2002": {"order_id": "2002", "tenant": "t2", "owner": "bob",
             "total": 99.00, "secret_note": "bob-private-9Z8Y7X6W5V4U"},
}
_DEMO_PATH_RE = re.compile(r"^/api/(v1|v2)/orders/(\w+)$")

_DEMO_CONFIG_YAML = """\
# Actors the tool can attribute traffic to and impersonate.
# Each actor's `auth` is used BOTH to recognize that actor's captured requests
# AND to replay as that actor. Keep real tokens out of version control.
actors:
  - name: alice
    tenant: t1
    role: member
    auth:
      header:
        Authorization: "Bearer token-alice"

  - name: bob
    tenant: t2
    role: member
    auth:
      header:
        Authorization: "Bearer token-bob"
"""


def demo_server(host: str = "127.0.0.1", port: int = 8799):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def _auth(self):
            tok = self.headers.get("Authorization", "").replace("Bearer ", "").strip()
            return _DEMO_USERS.get(tok)

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            m = _DEMO_PATH_RE.match(self.path)
            if not m:
                return self._send(404, {"error": "not found"})
            version, oid = m.group(1), m.group(2)
            user = self._auth()
            if not user:
                return self._send(401, {"error": "unauthorized"})
            order = _DEMO_ORDERS.get(oid)
            if not order:
                return self._send(404, {"error": "order not found"})
            if version == "v2" and order["tenant"] != user["tenant"]:
                return self._send(403, {"error": "forbidden"})
            # v1 forgets the ownership check -> IDOR
            return self._send(200, order)

    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"mock vulnerable server on http://{host}:{port}")
    srv.serve_forever()


def demo_capture(out: str, base: str = "http://127.0.0.1:8799"):
    """Generate a HAR of legitimate traffic: each user views only their OWN order.

    The point: authzgraph never sees a cross-tenant request in the capture. It
    has to *infer* that bob could reach alice's order, plan that probe, confirm it.
    """
    import requests
    sessions = [("token-alice", "1001"), ("token-bob", "2002")]
    entries = []
    for token, oid in sessions:
        for ver in ("v1", "v2"):
            url = f"{base}/api/{ver}/orders/{oid}"
            r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
            entries.append({
                "request": {
                    "method": "GET", "url": url,
                    "headers": [{"name": "Authorization", "value": f"Bearer {token}"}],
                    "queryString": [], "postData": {"text": ""},
                },
                "response": {
                    "status": r.status_code,
                    "headers": [{"name": k, "value": v} for k, v in r.headers.items()],
                    "content": {"text": r.text, "mimeType": "application/json"},
                },
            })
    har = {"log": {"version": "1.2", "creator": {"name": "authzgraph demo-capture"},
                   "entries": entries}}
    with open(out, "w") as fh:
        json.dump(har, fh, indent=2)
    print(f"wrote {len(entries)} entries -> {out}")


# ===========================================================================
# selftest — offline decision + id-detection tests (no network)
# ===========================================================================

def selftest() -> int:
    victim_legit = ('{"order_id":"1001","owner":"alice",'
                    '"secret_note":"alice-private-A1B2C3D4E5F6"}')

    def _case(victim_id="1001"):
        ex = HttpRecord(actor="bob", method="GET",
                        url="http://t/api/v1/orders/2002", host="t",
                        path="/api/v1/orders/2002")
        return TestCase(object_type="order", victim_id=victim_id, victim_actor="alice",
                        attacker_actor="bob", attack_kind="cross-tenant",
                        endpoint_key="GET t/api/v1/orders/{id}", exemplar=ex)

    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    f = evaluate(_case(), 200, victim_legit, victim_legit=victim_legit)
    check("leak_is_vulnerable", f.verdict == "VULNERABLE" and f.confidence >= 0.9)

    f = evaluate(_case(), 403, '{"error":"forbidden"}', victim_legit=victim_legit)
    check("403_is_safe", f.verdict == "NOT_VULNERABLE")

    f = evaluate(_case(), 200, '{"data":[]}', victim_legit=victim_legit)
    check("empty_200_not_flagged",
          f.verdict in ("NOT_VULNERABLE", "REVIEW") and f.verdict != "VULNERABLE")

    own = '{"order_id":"2002","owner":"bob","secret_note":"bob-private-9Z8Y7X6W5V4U"}'
    f = evaluate(_case(), 200, own, victim_legit=victim_legit)
    check("200_with_attacker_own_data_not_flagged", f.verdict != "VULNERABLE")

    check("id_uuid", id_format("550e8400-e29b-41d4-a716-446655440000") == "uuid")
    check("id_mongo", id_format("507f1f77bcf86cd799439011") == "mongo")
    check("id_named_int", looks_like_id("order_id", 1001) == "int")
    check("id_unnamed_int", looks_like_id("quantity", 1001) is None)
    check("type_from_field", type_from_field("order_id") == "order")

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print(f"{'ok ' if ok else 'FAIL'}  {n}")
    print(f"\n{len(checks) - len(failed)}/{len(checks)} tests passed")
    return 1 if failed else 0


# ===========================================================================
# cli
# ===========================================================================

def _load_actors(path: str) -> list[Actor]:
    import yaml
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    actors = []
    for a in cfg.get("actors", []):
        actors.append(Actor(
            name=a["name"], tenant=a.get("tenant"), role=a.get("role"),
            auth=a.get("auth", {}), match=a.get("match", []),
        ))
    return actors


def _build(args):
    actors = _load_actors(args.config)
    records = load_har(args.har, actors)
    attributed = sum(1 for r in records if r.actor)
    print(f"[+] loaded {len(records)} records, {attributed} attributed to actors",
          file=sys.stderr)
    model = ObjectModel()
    model.ingest(records)
    cases = plan(model, actors, include_unauth=not args.no_unauth,
                 max_per_type=args.max_per_type)
    print(f"[+] {len(model.types)} object types, {len(cases)} probes planned",
          file=sys.stderr)
    return actors, model, cases


def cmd_analyze(args):
    _, model, cases = _build(args)
    print(graph_summary(model))
    print(f"\n# Planned probes: {len(cases)} (run with --live to execute in scope)")
    kinds: dict[str, int] = {}
    for c in cases:
        kinds[c.attack_kind] = kinds.get(c.attack_kind, 0) + 1
    for k, v in kinds.items():
        print(f"  {k}: {v}")


def cmd_run(args):
    actors, model, cases = _build(args)
    cfg = ExecConfig(live=args.live, scope_hosts=args.scope,
                     rate_per_sec=args.rate)
    if args.live and not args.scope:
        sys.exit("[!] --live requires at least one --scope host")
    findings = run(model, cases, actors, cfg)
    print(findings_console(findings))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(findings_json(findings))
        print(f"\n[+] wrote JSON -> {args.json}", file=sys.stderr)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(findings_markdown(findings))
        print(f"[+] wrote markdown -> {args.markdown}", file=sys.stderr)


def cmd_demo_server(args):
    demo_server(args.host, args.port)


def cmd_demo_capture(args):
    demo_capture(args.out, args.base)


def cmd_demo_config(args):
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(_DEMO_CONFIG_YAML)
    print(f"wrote example actors config -> {args.out}")


def cmd_selftest(args):
    sys.exit(selftest())


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="authzgraph",
        description="Object-graph authorization fuzzer (IDOR/BOLA). "
                    "Authorized testing only.")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", required=True, help="actors YAML")
    common.add_argument("--har", required=True, help="captured traffic (HAR)")
    common.add_argument("--max-per-type", type=int, default=25)
    common.add_argument("--no-unauth", action="store_true",
                        help="skip unauthenticated probes")

    a = sub.add_parser("analyze", parents=[common], help="build graph + plan (no requests)")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("run", parents=[common], help="execute probes in scope")
    r.add_argument("--live", action="store_true", help="actually send requests")
    r.add_argument("--scope", action="append", default=[],
                   help="in-scope host (repeatable); required for --live")
    r.add_argument("--rate", type=float, default=1.0, help="requests per second")
    r.add_argument("--json", help="write findings JSON to this path")
    r.add_argument("--markdown", help="write findings markdown to this path")
    r.set_defaults(func=cmd_run)

    ds = sub.add_parser("demo-server", help="run the local mock vulnerable target")
    ds.add_argument("--host", default="127.0.0.1")
    ds.add_argument("--port", type=int, default=8799)
    ds.set_defaults(func=cmd_demo_server)

    dc = sub.add_parser("demo-capture", help="capture legit demo traffic to a HAR")
    dc.add_argument("out", help="output HAR path")
    dc.add_argument("--base", default="http://127.0.0.1:8799")
    dc.set_defaults(func=cmd_demo_capture)

    dcf = sub.add_parser("demo-config", help="write the example actors YAML")
    dcf.add_argument("out", help="output YAML path")
    dcf.set_defaults(func=cmd_demo_config)

    st = sub.add_parser("selftest", help="run offline decision/id tests (no network)")
    st.set_defaults(func=cmd_selftest)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
