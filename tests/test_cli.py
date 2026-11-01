import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import ROOT, q, store  # noqa: E402

GATE = os.path.join(ROOT, "gate.py")
CASES = os.path.join(ROOT, "cases")


def proc(args, cwd):
    return subprocess.run([sys.executable, GATE] + args, capture_output=True, text=True, cwd=str(cwd))


def test_process_exit_codes(tmp_path):
    mp, lp = store(tmp_path)
    r = proc([mp, lp], tmp_path)
    assert r.returncode == 0 and r.stdout.rstrip().endswith("gate: PASS chunks=5 queries=2 refusals=0 findings=0")
    mp, lp = store(tmp_path, log=[q("q1", "alpha", ["b1"])])
    r = proc([mp, lp], tmp_path)
    assert r.returncode == 1 and "FINDING CROSS_TENANT" in r.stdout
    r = proc([mp + ".missing", lp], tmp_path)
    assert r.returncode == 2 and r.stdout == "" and "BAD INPUT" in r.stderr


def test_argparse_errors_and_help(tmp_path):
    assert proc([], tmp_path).returncode == 2
    assert proc(["only-one"], tmp_path).returncode == 2
    assert proc(["a", "b", "--nope"], tmp_path).returncode == 2
    h = proc(["--help"], tmp_path)
    assert h.returncode == 0 and "store_manifest.json" in h.stdout and "--report" in h.stdout


def test_report_flag_writes_json(tmp_path):
    mp, lp = store(tmp_path)
    r = proc([mp, lp, "--report", "out.json"], tmp_path)
    assert r.returncode == 0 and os.path.exists(os.path.join(str(tmp_path), "out.json"))


def test_process_output_is_deterministic(tmp_path):
    mp, lp = store(tmp_path, log=[q("q1", "alpha", ["b1", "b2"])])
    a = proc([mp, lp, "--report", "r1.json"], tmp_path)
    b = proc([mp, lp, "--report", "r2.json"], tmp_path)
    assert a.returncode == b.returncode == 1 and a.stdout == b.stdout
    assert open(os.path.join(str(tmp_path), "r1.json"), "rb").read() == open(os.path.join(str(tmp_path), "r2.json"), "rb").read()


def test_case_folders_cover_pass_finding_and_refuse_for_every_check():
    names = sorted(os.listdir(CASES))
    assert len(names) >= 16
    want = ["pass_clean", "finding_cross_tenant", "refuse_acl_missing", "refuse_hash_mismatch", "refuse_text_missing",
            "finding_stale", "pass_age_exactly_at_max", "refuse_dim_mixed", "refuse_dim_policy_only",
            "finding_poison_retrieved_ignore", "finding_poison_store_only", "finding_answer_leak_not_retrieved",
            "pass_answer_below_bound", "refuse_orphan_retrieval", "exit2_manifest_not_json", "exit2_log_file_missing"]
    for w in want:
        assert w in names, w
    for n in names:
        assert os.path.exists(os.path.join(CASES, n, "expected.json")), n


def test_evaluate_rejects_arguments_it_does_not_take():
    import subprocess
    import sys as _sys
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = subprocess.run([_sys.executable, os.path.join(here, "evaluate.py"), "--bogus"],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "usage" in r.stderr and r.stdout == ""
