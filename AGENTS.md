# Verifying this repository

Purpose: Show that a vector store tenant boundary check refuses a missing acl, a tampered chunk, a mixed-model store and an orphan retrieval, reports cross-tenant retrieval, stale chunks, poisoned chunk text and answer leakage with the bound printed, and that the test suite kills every seeded defect in the gate.

Verify: `bash run.sh`

Pass condition: exit code 0, a last evaluator line `cases: N/N match` with equal numbers, and this exact output line from the mutation step (leading spaces ignored): `mutants: K/K killed` with equal numbers.

Scope: synthetic data, offline, standard library only, Python 3.9 compatible.

Limitations: Pattern and overlap heuristics find shapes, not intent. The manifest and the query log are the evidence; a retrieval that was never logged is not seen. Framework mappings are the author's reading, not an auditor's opinion. Engineering evidence, not legal advice, no certification claimed.

Anything else = not verified.
