# Authorize-Graph-
An object-graph authorization fuzzer for finding IDOR / BOLA bugs.

[README-5.md](https://github.com/user-attachments/files/32942564/README-5.md)
# authzgraph

An **object-graph authorization fuzzer** for finding IDOR / BOLA bugs.

Replay-based authz tools (Autorize, Auth Analyzer, AuthMatrix) take one request
you captured as user A, resend it as user B, and tell you if the response
changed. They have no model of the application — *you* still have to find every
object and every path to it by hand.

authzgraph builds the model for you. It ingests captured traffic from two or more
accounts, learns the ID formats, works out which endpoints **produce** and
**consume** each object type, correlates the same object type across REST paths,
GraphQL operations, and API versions, then **plans and tests cross-tenant,
cross-role, and unauthenticated access to every object over every path** — and
uses response-diffing with victim-specific markers to keep false positives down.

The discriminating question it answers is not "did the status change?" but
**"did the attacker get back data that is uniquely the victim's?"**

---

## ⚠️ Authorized use only

Live probing sends real cross-account requests. Only run `--live` against systems
you own or a bug-bounty / pentest program that has **explicitly authorized** you,
and stay inside the declared scope. The tool enforces a host allowlist and
defaults to dry-run, but the responsibility is yours.

---

## Install

```bash
pip install -r requirements.txt
```

## Quick start (self-contained demo)

The repo ships a deliberately-vulnerable target: `v1` orders leak across tenants
(IDOR), `v2` is correctly fixed.

```bash
# 1. run the mock target (separate terminal)
python examples/mock_vuln_server.py

# 2. capture legitimate traffic — each user views only their OWN order
python examples/make_capture.py examples/capture.har

# 3. build the object graph and see the probes it plans (sends nothing)
python -m authzgraph.cli analyze --config examples/config.yaml --har examples/capture.har

# 4. execute the probes in scope and evaluate
python -m authzgraph.cli run --config examples/config.yaml --har examples/capture.har \
    --scope 127.0.0.1 --live --rate 5 --markdown findings.md
```

Expected result: the two `v1` cross-tenant reads are flagged **VULNERABLE** (the
victim's private `secret_note` comes back), while `v2` (403) and the
unauthenticated probes (401) are **NOT_VULNERABLE**. The tool never saw a
cross-tenant request in the capture — it inferred and confirmed the bug.

## Real-world use

1. **Capture** normal traffic for 2+ accounts (different tenants, and/or
   different roles in one tenant) with Burp/mitmproxy/the browser, and export a
   HAR. Include mobile-app traffic in the capture to pull older/internal API
   versions into the graph automatically.
2. **Describe the accounts** in a YAML config (see `examples/config.yaml`): each
   actor's tenant, role, and the auth header/cookie that both identifies its
   captured requests and is used to replay as it.
3. `analyze` to review the object graph and planned probes.
4. `run --live --scope <in-scope-host>` to execute and get findings as console
   output, JSON (`--json`), and a HackerOne-ready markdown report (`--markdown`).

## How it works

```
 HAR capture ─▶ ingest ─▶ id-detect ─▶ object graph ─▶ planner ─▶ executor ─▶ diff ─▶ report
 (2+ accounts)            learn ID     produce/consume  cross-     scope-gated  marker-  console/
                          formats &    edges, cross-    tenant /   rate-limited  based   json/
                          object types protocol/version role /     replay       verdict  markdown
                                       correlation      unauth
```

| Stage | File | What it does |
|-------|------|--------------|
| ingest | `ingest.py` | Parse HAR, attribute each request to an actor by its auth material, detect GraphQL |
| id-detect | `iddetect.py` | Classify values as uuid/int/mongo/jwt/hashid; infer object type from field & path context |
| graph | `graph.py` | Normalize endpoints to templates; build produce/consume edges; correlate a type across versions & protocols |
| planner | `planner.py` | Find victim-owned objects; plan cross-tenant / cross-role / unauth probes over every consuming endpoint |
| executor | `executor.py` | Clone an exemplar, swap in the victim's id + attacker's session; scope-gated, rate-limited, dry-run by default |
| diff | `diff.py` | Decide VULNERABLE / NOT_VULNERABLE / REVIEW using victim markers + similarity to victim vs. forbidden baselines |
| report | `report.py` | Console summary, JSON, markdown |

## Verdicts

- **VULNERABLE** — attacker got a 2xx whose body carries the victim's own
  markers (the object id and/or high-entropy fields) and closely matches the
  victim's legitimate response.
- **NOT_VULNERABLE** — access denied (401/403/404) or the body matches the
  known empty/forbidden baseline with no victim markers.
- **REVIEW** — ambiguous (2xx with partial signals, 404-with-markers, 5xx).
- **PLANNED** — dry-run only; the request was built but not sent.

## Tests

```bash
python tests/test_pipeline.py        # or: python -m pytest -q
```

## Roadmap / extension points

- Live proxy ingestion (mitmproxy addon) in addition to HAR
- Seed the graph from OpenAPI/Swagger and GraphQL introspection (`ingest.py`)
- Deeper GraphQL: node-by-global-id enumeration, nested-field authz, aliasing, batching
- WebSocket per-message authz probing
- State-changing probe support (PUT/PATCH/DELETE) with safe-mode guards
- Smarter id-substitution when an endpoint consumes multiple id types

## License

MIT. Provided for authorized security testing and education.
