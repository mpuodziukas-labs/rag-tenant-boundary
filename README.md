# rag-tenant-boundary

Proves: a vector store manifest and its retrieval log are checked fail-closed for cross-tenant retrieval, missing acls, tampered chunks, stale chunks, mixed embedding dimensions, poisoned chunk text and answer leakage, and a test suite kills seeded defects in the gate. Verify in 60s: `python3 evaluate.py`

Engineering evidence, not legal advice, no certification claimed. All data is synthetic and labeled synthetic.

## The problem

OWASP LLM08:2025 (Vector and Embedding Weaknesses) is about the embedding store itself: who may retrieve which chunk, whether the stored text is the text that was ingested, and whether retrieved text can steer the model. A groundedness check on the answer does not cover it. A multi-tenant store is often trusted because the query filter should be set. Nothing records what was retrieved or what the answer repeated.

This repo is one CLI, `python3 gate.py`. It turns a store manifest and a retrieval log into a verdict, an exit code and an optional JSON report.

## Run it

```
python3 gate.py <store_manifest.json> <query_log.jsonl> [--report out.json]
python3 evaluate.py          # case table, last line: cases: N/N match
bash run.sh                  # table, pytest, mutants
python3 make_cases.py        # regenerates cases/ from the hand-written answer key
```

Exit codes: 0 pass, 1 refuse or finding, 2 bad input (unreadable file, bad arguments, a manifest that is not strict JSON). Chunk text files sit beside the manifest as `<chunk_id>.txt`. Output is deterministic. The report holds the sha256 of every input read.

Manifest shape: a `policy` block (`allowed_tenants`, `max_chunk_age_days`, `require_acl`, `embedding_dim`, `as_of`) and a `chunks` list (`chunk_id`, `tenant`, `source_doc`, `sha256`, `acl`, `ingested_at`, `embedding_dim`). Log line shape: `query_id`, `tenant`, `chunk_ids`, `scores`, `answer`, and an optional `roles` list. `as_of` is in the policy so a run never depends on the clock.

## What it checks

Refusals (verdict REFUSE):

- Missing, empty or malformed acl on any chunk (ACL_MISSING).
- Chunk text whose sha256 differs from the manifest, or a missing text file (HASH_MISMATCH, TEXT_MISSING).
- Mixed embedding dimensions across chunks, or a dimension that differs from policy (DIM_MIXED, DIM_POLICY).
- A retrieved chunk_id that is not in the manifest (ORPHAN_RETRIEVAL).
- A malformed or duplicate log line, an empty log, a missing manifest field, an invalid policy, a tenant outside the policy list (LOG_MALFORMED, LOG_DUP, LOG_EMPTY, MANIFEST_FIELD, POLICY_INVALID, TENANT_UNKNOWN), a repeated chunk id (DUP_CHUNK).

Findings (verdict FINDING):

- Cross-tenant retrieval: a retrieved chunk whose acl lacks the querying tenant and every role on the query. The chunk and the tenant are named (CROSS_TENANT).
- Stale chunks past the policy age (STALE).
- Instruction strings in chunk text: ignore-previous phrasing, role prefixes, role tags, "you must" (POISON_RETRIEVED when a query retrieved it, POISON_STORE when it sits unretrieved).
- Answer leakage: the normalized final answer shares a longest common substring with a chunk the tenant may not read, at or above the bound. The bound is printed in every run (ANSWER_LEAK).

Every run prints a per-query table, a count for each code, the bound and a crosswalk block. A refusal outranks a finding. The comparator for the leak score is greater-than-or-equal; for age it is strictly greater-than.

## Mapping

| Check | OWASP LLM Top 10 2025 | NIST AI RMF | NIST SP 800-53 | EU AI Act |
|-------|-----------------------|-------------|----------------|-----------|
| Cross-tenant retrieval, missing acl | LLM08 | | AC-3, AC-6 | |
| Hash-pinned chunks, orphan retrieval, mixed dimension | LLM08 | MEASURE 2.7 | | Art. 15 |
| Stale chunks | LLM08 | MANAGE 2.2 | | Art. 10 |
| Poisoned chunk text | LLM08 | MEASURE 2.7 | | Art. 15 |
| Answer leakage | LLM02, LLM08 | | AC-3, AC-6 | |

ISO/IEC 42001: clause not verified from public text, so no clause is mapped. SP 800-53 and EU AI Act items are cited by id only. Quoted text and URLs are in `SOURCES.md`. The mapping is the author's reading, not an auditor's opinion.

## Honesty

The cases are synthetic and were written for this repository. No language model runs in the loop: the gate and the evaluation script import only the Python standard library. The checks and the cases were written together, so the case count that evaluate.py prints is a consistency check, not a claim that the gate generalizes. Tenant names and chunk ids in the fixtures are test fixtures, not real tenants. Nothing here was run against production data.

## Limitations

- The manifest and the log are the evidence. A retrieval that was never logged, or a log that was edited, is not seen.
- Instruction patterns and substring overlap find shapes, not intent. A paraphrased leak below the bound, or a new injection phrasing, can pass.
- The acl model is tenant name or role name equality. It does not evaluate group nesting, expiry or attribute rules.
- The leak check compares the answer with chunk text. It does not read the embedding vectors, so it cannot see a leak through similarity alone.
- The mutation check seeds defects in `gate.py` only. It does not prove the absence of other defects.
- `tests/dbg_runner.py` is an empty stub left from the build.
- Numbers for cases, tests and mutants are those the runner prints. This file states none of its own.
