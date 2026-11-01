"""Shared helpers. Paths resolve from this file, so a copy of the repo tests itself.
All data here is synthetic. The store builders reuse make_cases so the shapes cannot drift."""
import contextlib
import copy
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import gate  # noqa: E402
import make_cases as mc  # noqa: E402

TEXT, base, chunk, q, sha, jl = mc.TEXT, mc.base, mc.chunk, mc.q, mc.sha, mc.jl


def call(argv):
    """Run gate.main in-process. Returns (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = gate.main(argv)
    return rc, out.getvalue(), err.getvalue()


def write(path, text):
    mode = "wb" if isinstance(text, bytes) else "w"
    with open(path, mode) as fh:
        fh.write(text)


def store(tmp, man=None, texts=None, log=None, raw_log=None, raw_man=None, skip=(), no_log=False):
    """Write a store and log under tmp. Returns (manifest path, log path)."""
    d = str(tmp)
    allt = dict(TEXT, **(texts or {}))
    for cid, body in allt.items():
        if cid not in skip:
            write(os.path.join(d, cid + ".txt"), body)
    mp, lp = os.path.join(d, "manifest.json"), os.path.join(d, "query_log.jsonl")
    m = man if man is not None else base()
    write(mp, raw_man if raw_man is not None else json.dumps(m, sort_keys=True))
    if not no_log:
        write(lp, raw_log if raw_log is not None else jl(log if log is not None else mc.GOOD_LOG))
    return mp, lp


def run(tmp, extra=(), **kw):
    """Build the store, run the gate, return (rc, report or None, stdout)."""
    mp, lp = store(tmp, **kw)
    rp = os.path.join(str(tmp), "report.json")
    rc, out, err = call([mp, lp, "--report", rp] + list(extra))
    rep = json.load(open(rp)) if os.path.exists(rp) else None
    return rc, rep, out


def codes(rep):
    return sorted(set(r["code"] for r in rep["refusals"] + rep["findings"]))


def of(rep, code):
    return [r for r in rep["refusals"] + rep["findings"] if r["code"] == code]


def qv(rep):
    return dict((r["query_id"], r["verdict"]) for r in rep["queries"])


def with_text(cid, body):
    """A manifest whose chunk cid hashes the given body, plus the texts override."""
    m = base()
    chunk(m, cid)["sha256"] = sha(body)
    return m, {cid: body}


def clone(m):
    return copy.deepcopy(m)
