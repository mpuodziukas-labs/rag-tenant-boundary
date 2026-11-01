#!/usr/bin/env python3
"""Mutation check. Each mutant changes one spot in gate.py inside a throwaway copy of the
repo (a temporary directory, cleaned up by the interpreter when the run ends). The pytest suite
then runs on the copy. A mutant is killed when the suite exits non-zero. A spot that does not
occur exactly once in gate.py is reported INVALID and does not count as killed."""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
B = "gate.py"

MUTANTS = [
    # check 7: answer leak
    ("leak_bound_gt_instead_of_ge", "if score >= bound:", "if score > bound:"),
    ("leak_ignores_acl", 'if cid not in norm_text or allowed(e, t, q["roles"]):', "if cid not in norm_text:"),
    ("leak_never_flags", "if score >= bound:", "if False:"),
    ("lcs_does_not_extend_runs", "cur[j] = prev[j - 1] + 1", "cur[j] = 1"),
    ("normalize_drops_lowercase", 'return " ".join(unicodedata.normalize("NFKC", text).lower().split())', 'return " ".join(unicodedata.normalize("NFKC", text).split())'),
    ("normalize_drops_nfkc", 'return " ".join(unicodedata.normalize("NFKC", text).lower().split())', 'return " ".join(text.lower().split())'),
    ("normalize_drops_whitespace_collapse", 'return " ".join(unicodedata.normalize("NFKC", text).lower().split())', 'return unicodedata.normalize("NFKC", text).lower()'),
    ("answer_not_normalized", 'ans = normalize(q["answer"])', 'ans = q["answer"]'),
    ("chunk_text_not_normalized", 'normalize(e["text"])) for cid, e in chunks.items()', 'e["text"]) for cid, e in chunks.items()'),
    # check 1: cross tenant and roles
    ("cross_tenant_never_flags", 'if not allowed(e, t, q["roles"]):', "if False:"),
    ("roles_ignored", "return tenant in acl or any(r in acl for r in roles)", "return tenant in acl"),
    ("empty_roles_allow_everything", "any(r in acl for r in roles)", "all(r in acl for r in roles)"),
    ("tenant_match_dropped", "return tenant in acl or any", "return any"),
    # check 2: acl
    ("acl_check_skipped", "if not is_str_list(acl):", "if False:"),
    ("empty_list_accepted", "isinstance(v, list) and len(v) > 0 and", "isinstance(v, list) and"),
    # check 3: hash pin and path safety
    ("hash_check_skipped", 'if sha256_hex(raw) != c["sha256"]:', "if False:"),
    ("text_missing_ignored", "if not os.path.isfile(path):", "if False:"),
    ("chunk_id_allows_traversal", 'r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$"', 'r"^[A-Za-z0-9_./-]{1,80}$"'),
    ("sha_shape_unchecked", 'not SHA_RE.match(c.get("sha256"))', "False"),
    ("input_hash_wrong", '"sha256": sha256_hex(raw), "bytes": len(raw)', '"sha256": sha256_hex(b""), "bytes": len(raw)'),
    # check 4: stale
    ("stale_ge_instead_of_gt", '.days > pol["max_chunk_age_days"]:', '.days >= pol["max_chunk_age_days"]:'),
    ("stale_never_flags", "if loaded and as_of is not None and", "if False and"),
    ("stale_age_sign_flipped", "(as_of - ing).days > pol", "(ing - as_of).days > pol"),
    # check 5: embedding dim
    ("dim_mixed_never_flags", "if len(dims) > 1:", "if False:"),
    ("dim_mixed_needs_three", "if len(dims) > 1:", "if len(dims) > 2:"),
    ("dim_policy_never_flags", 'if loaded and c["embedding_dim"] != pol["embedding_dim"]:', "if False:"),
    ("dim_bool_accepted", 'if not is_int(c.get("embedding_dim")) or c.get("embedding_dim") <= 0:', 'if not isinstance(c.get("embedding_dim"), int) or c.get("embedding_dim") <= 0:'),
    # check 6: poison
    ("poison_lowercase_dropped", "low = text.lower()", "low = text"),
    ("poison_disregard_dropped", r"\b(?:ignore|disregard|forget)\b", r"\b(?:ignore|forget)\b"),
    ("poison_assistant_prefix_dropped", r"(?:system|assistant|developer)\s*:", r"(?:system|developer)\s*:"),
    ("poison_im_start_dropped", "system|assistant|user|im_start|im_end", "system|assistant|user|im_end"),
    ("poison_you_must_dropped", '    ("you_must", re.compile(r"\\byou must\\b")),\n', ""),
    ("poison_store_never_flags", "if cid not in retrieved_poison:", "if False:"),
    ("poison_store_also_when_retrieved", "if cid not in retrieved_poison:", "if True:"),
    ("poison_retrieved_never_flags", "if cid in poisoned:\n                retrieved_poison.add(cid)", "if False:\n                retrieved_poison.add(cid)"),
    # check 8: orphan
    ("orphan_ignored", "if e is None and cid in declared:", "if e is None:"),
    ("orphan_unusable_reported_too", "if e is None and cid in declared:\n                continue", "if False:\n                continue"),
    # log structure
    ("log_not_object_accepted", "if not isinstance(obj, dict):", "if False:"),
    ("scores_length_unchecked", "elif isinstance(ci, list) and len(ci) != len(sc):", "elif False:"),
    ("bool_score_accepted", " and not isinstance(x, bool) and math", " and math"),
    ("duplicate_query_ignored", "if qid in ids:", "if False:"),
    ("empty_log_accepted", "if not queries and not any(", "if False and not any("),
    ("duplicate_keys_accepted", "if len(keys) != len(set(keys)):", "if False:"),
    ("nan_accepted", 'raise ValueError("non-finite number " + name)', "return 0.0"),
    # manifest structure and policy
    ("duplicate_chunk_ignored", "if cid in seen:", "if False:"),
    ("policy_acl_flag_ignored", 'if pol.get("require_acl") is not True:', "if False:"),
    ("chunk_tenant_unchecked", 'if loaded and c["tenant"] not in pol["allowed_tenants"]:', "if False:"),
    ("query_tenant_unchecked", 'if loaded and t not in loaded[0]["allowed_tenants"]:', "if False:"),
    ("as_of_unchecked", "if not m:\n        refusals.append(rec(\"POLICY_INVALID\", \"policy.as_of", "if False:\n        refusals.append(rec(\"POLICY_INVALID\", \"policy.as_of"),
    # verdicts and exit codes
    ("refusal_does_not_outrank_finding", 'if refusals:\n        verdict = "REFUSE"', 'if False:\n        verdict = "REFUSE"'),
    ("finding_verdict_dropped", 'elif findings:\n        verdict = "FINDING"', 'elif False:\n        verdict = "FINDING"'),
    ("finding_exits_zero", 'return 0 if rep["verdict"] == "PASS" else 1', "return 0"),
    ("bad_input_exits_one", 'sys.stderr.write("BAD INPUT: %s\\n" % exc)\n        return 2', 'sys.stderr.write("BAD INPUT: %s\\n" % exc)\n        return 1'),
]


def run_suite(root):
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x"],
                       cwd=root, capture_output=True, text=True)
    return r.returncode


def main():
    with open(os.path.join(HERE, B), encoding="utf-8") as fh:
        source = fh.read()
    if run_suite(HERE) != 0:
        print("control: suite fails unmodified")
        return 1
    print("control: suite passes unmodified")
    killed = 0
    for name, old, new in MUTANTS:
        if source.count(old) != 1:
            print("INVALID %s (spot found %d times)" % (name, source.count(old)))
            continue
        mutated = source.replace(old, new)
        try:
            compile(mutated, B, "exec")
        except SyntaxError:
            print("INVALID %s (does not compile)" % name)
            continue
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "repo")
            shutil.copytree(HERE, root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
            with open(os.path.join(root, B), "w", encoding="utf-8") as fh:
                fh.write(mutated)
            dead = run_suite(root) != 0
        killed += dead
        print("%s %s" % ("KILLED  " if dead else "SURVIVED", name))
    print("mutants: %d/%d killed" % (killed, len(MUTANTS)))
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
