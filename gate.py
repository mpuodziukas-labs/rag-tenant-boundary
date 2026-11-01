#!/usr/bin/env python3
"""rag-tenant-boundary: fail-closed checks on a vector store manifest and a retrieval log.

usage: python3 gate.py <store_manifest.json> <query_log.jsonl> [--report out.json]

Exit 0 pass, 1 refuse or finding, 2 bad input (unreadable file or bad arguments).
Chunk text files sit beside the manifest as <chunk_id>.txt. Standard library only.
All data shipped with this repo is synthetic."""
import argparse
import hashlib
import json
import math
import os
import re
import sys
import unicodedata
from datetime import date

# Every bound lives in this one table and is printed in every run.
BOUNDS = {"answer_leak_lcs": 40}

REFUSE_CODES = ["MANIFEST_FIELD", "POLICY_INVALID", "ACL_MISSING", "TEXT_MISSING", "HASH_MISMATCH",
                "DIM_MIXED", "DIM_POLICY", "DUP_CHUNK", "TENANT_UNKNOWN", "LOG_MALFORMED",
                "LOG_DUP", "LOG_EMPTY", "ORPHAN_RETRIEVAL"]
FINDING_CODES = ["CROSS_TENANT", "STALE", "POISON_RETRIEVED", "POISON_STORE", "ANSWER_LEAK"]

CHUNK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:T[0-9:.]+Z?)?$")

POISON_RES = [
    ("ignore_previous", re.compile(r"\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier)\b")),
    ("role_prefix", re.compile(r"(?:^|\n)\s*(?:system|assistant|developer)\s*:")),
    ("role_tag", re.compile(r"<\|?\s*(?:system|assistant|user|im_start|im_end)\s*\|?>|\[/?inst\]")),
    ("you_must", re.compile(r"\byou must\b")),
]

CROSSWALK = [
    ("cross-tenant retrieval, missing acl", "OWASP LLM08:2025", "NIST SP 800-53 AC-3, AC-6"),
    ("hash-pinned chunks, orphan retrieval, mixed embedding dim", "OWASP LLM08:2025", "NIST AI RMF MEASURE 2.7; EU AI Act Art. 15"),
    ("stale chunks", "OWASP LLM08:2025", "NIST AI RMF MANAGE 2.2; EU AI Act Art. 10"),
    ("poisoned chunk text", "OWASP LLM08:2025", "NIST AI RMF MEASURE 2.7; EU AI Act Art. 15"),
    ("answer leakage", "OWASP LLM02:2025, LLM08:2025", "NIST SP 800-53 AC-3, AC-6"),
]


class BadInput(Exception):
    """Unreadable file or bad arguments: exit 2."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).lower().split())


def _no_dup_pairs(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _bad_const(name):
    raise ValueError("non-finite number " + name)


def parse_json(text: str):
    """Strict JSON: duplicate keys and NaN or Infinity are errors."""
    return json.loads(text, object_pairs_hook=_no_dup_pairs, parse_constant=_bad_const)


def is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def is_str_list(v) -> bool:
    return isinstance(v, list) and len(v) > 0 and all(isinstance(x, str) and x for x in v)


def longest_common_substring(a: str, b: str) -> int:
    """Length of the longest common substring, two-row dynamic programming."""
    if not a or not b:
        return 0
    best = 0
    prev = [0] * (len(b) + 1)
    for i in range(1, len(a) + 1):
        cur = [0] * (len(b) + 1)
        ai = a[i - 1]
        for j in range(1, len(b) + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
                if cur[j] > best:
                    best = cur[j]
        prev = cur
    return best


def poison_hits(text: str):
    low = text.lower()
    return [name for name, rx in POISON_RES if rx.search(low)]


def read_input(path: str, inputs: list) -> bytes:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise BadInput("cannot read %s: %s" % (path, exc.strerror or type(exc).__name__))
    inputs.append({"file": os.path.basename(path), "sha256": sha256_hex(raw), "bytes": len(raw)})
    return raw


def rec(code, detail, query=None, chunk=None, tenant=None):
    return {"code": code, "query": query, "chunk": chunk, "tenant": tenant, "detail": detail}


def load_policy(man, refusals):
    pol = man.get("policy") if isinstance(man, dict) else None
    if not isinstance(pol, dict):
        refusals.append(rec("MANIFEST_FIELD", "policy block missing or not an object"))
        return None
    ok = True
    if not is_str_list(pol.get("allowed_tenants")):
        refusals.append(rec("POLICY_INVALID", "policy.allowed_tenants must be a non-empty list of strings"))
        ok = False
    if not is_int(pol.get("max_chunk_age_days")) or pol.get("max_chunk_age_days") < 0:
        refusals.append(rec("POLICY_INVALID", "policy.max_chunk_age_days must be an integer >= 0"))
        ok = False
    if not is_int(pol.get("embedding_dim")) or pol.get("embedding_dim") <= 0:
        refusals.append(rec("POLICY_INVALID", "policy.embedding_dim must be a positive integer"))
        ok = False
    if pol.get("require_acl") is not True:
        refusals.append(rec("POLICY_INVALID", "policy.require_acl must be true"))
        ok = False
    as_of = pol.get("as_of")
    m = DATE_RE.match(as_of) if isinstance(as_of, str) else None
    if not m:
        refusals.append(rec("POLICY_INVALID", "policy.as_of must be YYYY-MM-DD"))
        ok = False
    return (pol, m.group(1)) if ok else None


def parse_date(s):
    m = DATE_RE.match(s) if isinstance(s, str) else None
    if not m:
        return None
    try:
        y, mo, d = [int(x) for x in m.group(1).split("-")]
        return date(y, mo, d)
    except ValueError:
        return None


def check_manifest(man, data_dir, inputs):
    """Return (chunks by id, refusals, findings, policy)."""
    refusals, findings = [], []
    chunks = {}
    loaded = load_policy(man, refusals)
    raw_chunks = man.get("chunks") if isinstance(man, dict) else None
    if not isinstance(raw_chunks, list) or not raw_chunks:
        refusals.append(rec("MANIFEST_FIELD", "chunks missing or empty"))
        return chunks, refusals, findings, loaded, set()
    pol, as_of_s = loaded if loaded else ({}, None)
    as_of = parse_date(as_of_s) if as_of_s else None
    seen = set()
    for idx, c in enumerate(raw_chunks):
        label = c.get("chunk_id") if isinstance(c, dict) and isinstance(c.get("chunk_id"), str) else "#%d" % idx
        if not isinstance(c, dict):
            refusals.append(rec("MANIFEST_FIELD", "chunk entry %s is not an object" % label, chunk=label))
            continue
        cid = c.get("chunk_id")
        if not isinstance(cid, str) or not CHUNK_ID_RE.match(cid):
            refusals.append(rec("MANIFEST_FIELD", "chunk %s has a missing or unsafe chunk_id" % label, chunk=label))
            continue
        if cid in seen:
            refusals.append(rec("DUP_CHUNK", "chunk_id listed twice", chunk=cid))
            continue
        seen.add(cid)
        good = True
        for fld in ("tenant", "source_doc", "ingested_at"):
            if not isinstance(c.get(fld), str) or not c.get(fld):
                refusals.append(rec("MANIFEST_FIELD", "chunk %s field %s missing or not a string" % (cid, fld), chunk=cid))
                good = False
        if not isinstance(c.get("sha256"), str) or not SHA_RE.match(c.get("sha256")):
            refusals.append(rec("MANIFEST_FIELD", "chunk %s field sha256 missing or not 64 lowercase hex" % cid, chunk=cid))
            good = False
        if not is_int(c.get("embedding_dim")) or c.get("embedding_dim") <= 0:
            refusals.append(rec("MANIFEST_FIELD", "chunk %s field embedding_dim missing or not a positive integer" % cid, chunk=cid))
            good = False
        acl = c.get("acl")
        if not is_str_list(acl):
            refusals.append(rec("ACL_MISSING", "chunk %s has no usable acl (missing, empty or not a list of strings)" % cid, chunk=cid))
            good = False
        if not good:
            continue
        ing = parse_date(c["ingested_at"])
        if ing is None:
            refusals.append(rec("MANIFEST_FIELD", "chunk %s ingested_at is not YYYY-MM-DD" % cid, chunk=cid))
            continue
        entry = {"chunk_id": cid, "tenant": c["tenant"], "acl": list(acl), "sha256": c["sha256"],
                 "dim": c["embedding_dim"], "ingested": ing, "text": None}
        if loaded and c["tenant"] not in pol["allowed_tenants"]:
            refusals.append(rec("TENANT_UNKNOWN", "chunk %s tenant %s is not in policy.allowed_tenants" % (cid, c["tenant"]), chunk=cid, tenant=c["tenant"]))
        path = os.path.join(data_dir, cid + ".txt")
        if not os.path.isfile(path):
            refusals.append(rec("TEXT_MISSING", "chunk %s has no text file %s" % (cid, cid + ".txt"), chunk=cid))
        else:
            raw = read_input(path, inputs)
            if sha256_hex(raw) != c["sha256"]:
                refusals.append(rec("HASH_MISMATCH", "chunk %s text sha256 differs from the manifest (tampered store)" % cid, chunk=cid))
            try:
                entry["text"] = raw.decode("utf-8")
            except UnicodeDecodeError:
                refusals.append(rec("MANIFEST_FIELD", "chunk %s text is not valid utf-8" % cid, chunk=cid))
        chunks[cid] = entry
        if loaded and as_of is not None and (as_of - ing).days > pol["max_chunk_age_days"]:
            findings.append(rec("STALE", "chunk %s is %d days old, max %d" % (cid, (as_of - ing).days, pol["max_chunk_age_days"]), chunk=cid))
        if loaded and c["embedding_dim"] != pol["embedding_dim"]:
            refusals.append(rec("DIM_POLICY", "chunk %s embedding_dim %d differs from policy %d" % (cid, c["embedding_dim"], pol["embedding_dim"]), chunk=cid))
    dims = sorted(set(e["dim"] for e in chunks.values()))
    if len(dims) > 1:
        refusals.append(rec("DIM_MIXED", "store mixes embedding dims %s (mixed-model store)" % dims))
    return chunks, refusals, findings, loaded, seen


def parse_log(text, chunks, refusals):
    """Return a list of valid query dicts; malformed lines become refusals."""
    queries, ids = [], set()
    lines = text.split("\n")
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        tag = "line %d" % n
        try:
            obj = parse_json(line)
        except ValueError as exc:
            refusals.append(rec("LOG_MALFORMED", "%s is not valid JSON (%s)" % (tag, exc)))
            continue
        if not isinstance(obj, dict):
            refusals.append(rec("LOG_MALFORMED", "%s is not an object" % tag))
            continue
        qid = obj.get("query_id")
        bad = []
        if not isinstance(qid, str) or not qid:
            bad.append("query_id")
        if not isinstance(obj.get("tenant"), str) or not obj.get("tenant"):
            bad.append("tenant")
        ci, sc = obj.get("chunk_ids"), obj.get("scores")
        if not isinstance(ci, list) or not all(isinstance(x, str) and x for x in ci):
            bad.append("chunk_ids")
        if not isinstance(sc, list) or not all(isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) for x in sc):
            bad.append("scores")
        elif isinstance(ci, list) and len(ci) != len(sc):
            bad.append("scores length")
        if not isinstance(obj.get("answer"), str):
            bad.append("answer")
        roles = obj.get("roles", [])
        if not isinstance(roles, list) or not all(isinstance(x, str) and x for x in roles):
            bad.append("roles")
        if bad:
            refusals.append(rec("LOG_MALFORMED", "%s bad or missing field(s): %s" % (tag, ", ".join(bad)), query=qid if isinstance(qid, str) else None))
            continue
        if qid in ids:
            refusals.append(rec("LOG_DUP", "query_id listed twice", query=qid))
            continue
        ids.add(qid)
        queries.append({"query_id": qid, "tenant": obj["tenant"], "roles": roles, "chunk_ids": ci,
                        "scores": sc, "answer": obj["answer"]})
    if not queries and not any(r["code"] == "LOG_MALFORMED" for r in refusals):
        refusals.append(rec("LOG_EMPTY", "query log has no queries"))
    return queries


def allowed(entry, tenant, roles):
    acl = entry["acl"]
    return tenant in acl or any(r in acl for r in roles)


def check_queries(queries, chunks, declared, refusals, findings, loaded):
    bound = BOUNDS["answer_leak_lcs"]
    poisoned = {}
    for cid, e in sorted(chunks.items()):
        if e["text"] is not None:
            hits = poison_hits(e["text"])
            if hits:
                poisoned[cid] = hits
    retrieved_poison = set()
    norm_text = dict((cid, normalize(e["text"])) for cid, e in chunks.items() if e["text"] is not None)
    for q in queries:
        t = q["tenant"]
        if loaded and t not in loaded[0]["allowed_tenants"]:
            refusals.append(rec("TENANT_UNKNOWN", "query tenant %s is not in policy.allowed_tenants" % t, query=q["query_id"], tenant=t))
        for cid in q["chunk_ids"]:
            e = chunks.get(cid)
            if e is None and cid in declared:
                continue  # listed in the manifest but unusable: already refused there
            if e is None:
                refusals.append(rec("ORPHAN_RETRIEVAL", "retrieved chunk %s is not in the manifest" % cid, query=q["query_id"], chunk=cid, tenant=t))
                continue
            if not allowed(e, t, q["roles"]):
                findings.append(rec("CROSS_TENANT", "chunk %s (acl %s) retrieved by tenant %s" % (cid, ",".join(e["acl"]), t), query=q["query_id"], chunk=cid, tenant=t))
            if cid in poisoned:
                retrieved_poison.add(cid)
                findings.append(rec("POISON_RETRIEVED", "retrieved chunk %s matches %s" % (cid, ",".join(poisoned[cid])), query=q["query_id"], chunk=cid, tenant=t))
        ans = normalize(q["answer"])
        for cid, e in sorted(chunks.items()):
            if cid not in norm_text or allowed(e, t, q["roles"]):
                continue
            score = longest_common_substring(ans, norm_text[cid])
            if score >= bound:
                findings.append(rec("ANSWER_LEAK", "answer reproduces chunk %s the tenant %s may not read: lcs=%d >= bound %d" % (cid, t, score, bound), query=q["query_id"], chunk=cid, tenant=t))
    for cid in sorted(poisoned):
        if cid not in retrieved_poison:
            findings.append(rec("POISON_STORE", "stored chunk %s matches %s (not retrieved in this log)" % (cid, ",".join(poisoned[cid])), chunk=cid))


def sort_key(r):
    return (r["code"], r["query"] or "", r["chunk"] or "", r["detail"])


def run(manifest_path, log_path):
    inputs = []
    mraw = read_input(manifest_path, inputs)
    lraw = read_input(log_path, inputs)
    refusals, findings = [], []
    try:
        man = parse_json(mraw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BadInput("manifest is not valid JSON: %s" % exc)
    chunks, mref, mfin, loaded, declared = check_manifest(man, os.path.dirname(os.path.abspath(manifest_path)), inputs)
    refusals += mref
    findings += mfin
    try:
        ltext = lraw.decode("utf-8")
    except UnicodeDecodeError:
        raise BadInput("query log is not valid utf-8")
    queries = parse_log(ltext, chunks, refusals)
    check_queries(queries, chunks, declared, refusals, findings, loaded)
    refusals.sort(key=sort_key)
    findings.sort(key=sort_key)
    if refusals:
        verdict = "REFUSE"
    elif findings:
        verdict = "FINDING"
    else:
        verdict = "PASS"
    rows = []
    for q in queries:
        qr = [r for r in refusals if r["query"] == q["query_id"]]
        qf = [f for f in findings if f["query"] == q["query_id"]]
        v = "REFUSE" if qr else ("FINDING" if qf else "PASS")
        codes = sorted(set(r["code"] for r in qr + qf))
        rows.append({"query_id": q["query_id"], "tenant": q["tenant"], "retrieved": len(q["chunk_ids"]),
                     "verdict": v, "codes": codes})
    counts = dict((c, 0) for c in REFUSE_CODES + FINDING_CODES)
    for r in refusals + findings:
        counts[r["code"]] += 1
    return {"verdict": verdict, "bounds": dict(BOUNDS), "inputs": inputs, "chunks": len(chunks),
            "queries": rows, "counts": counts, "refusals": refusals, "findings": findings}


def render(rep):
    out = ["| query | tenant | retrieved | verdict | codes |", "|---|---|---|---|---|"]
    for r in rep["queries"]:
        out.append("| %s | %s | %d | %s | %s |" % (r["query_id"], r["tenant"], r["retrieved"], r["verdict"], ",".join(r["codes"]) or "-"))
    out.append("")
    for r in rep["refusals"]:
        out.append("REFUSE %s %s" % (r["code"], r["detail"]))
    for f in rep["findings"]:
        out.append("FINDING %s %s" % (f["code"], f["detail"] if not f["query"] else "[%s] %s" % (f["query"], f["detail"])))
    out.append("")
    out.append("bound: answer leak is a normalized longest common substring >= %d characters" % rep["bounds"]["answer_leak_lcs"])
    out.append("counts: " + " ".join("%s=%d" % (c, rep["counts"][c]) for c in REFUSE_CODES + FINDING_CODES))
    out.append("crosswalk (the author's reading, see SOURCES.md):")
    for check, owasp, other in CROSSWALK:
        out.append("  %s -> %s; %s" % (check, owasp, other))
    out.append("gate: %s chunks=%d queries=%d refusals=%d findings=%d" % (
        rep["verdict"], rep["chunks"], len(rep["queries"]), len(rep["refusals"]), len(rep["findings"])))
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gate.py", description="Tenant boundary checks for a vector store manifest and a retrieval log.")
    ap.add_argument("manifest", help="store_manifest.json")
    ap.add_argument("query_log", help="query_log.jsonl")
    ap.add_argument("--report", help="write a JSON report here (sha256 of every input read)")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        rep = run(args.manifest, args.query_log)
    except BadInput as exc:
        sys.stderr.write("BAD INPUT: %s\n" % exc)
        return 2
    print(render(rep))
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                json.dump(rep, fh, indent=2, sort_keys=True)
                fh.write("\n")
        except OSError as exc:
            sys.stderr.write("BAD INPUT: cannot write report: %s\n" % (exc.strerror or type(exc).__name__))
            return 2
    return 0 if rep["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
