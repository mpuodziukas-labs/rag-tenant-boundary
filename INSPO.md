# Inspiration

Public repositories in the same space, with the star counts the GitHub search returned on 2026-11-01. Descriptions are the search one-liners. No claim is made about their internals, and nothing was copied. The search did not return an entry for the Ragas repository, so it is not listed.

| # | Repository | Stars | Known for (search one-liner) |
|---|------------|-------|------------------------------|
| 1 | langchain-ai/langchain | 148,806 | The agent engineering platform |
| 2 | run-llama/llama_index | 52,767 | Document processing platform for AI |
| 3 | milvus-io/milvus | 46,546 | Cloud-native vector database for scalable ANN search |
| 4 | qdrant/qdrant | 35,358 | Vector database and vector search engine |
| 5 | chroma-core/chroma | 29,616 | Search infrastructure for AI |
| 6 | pgvector/pgvector | 23,554 | Vector similarity search for Postgres |
| 7 | weaviate/weaviate | 16,933 | Open-source vector database with structured filtering |
| 8 | NVIDIA-NeMo/Guardrails | 7,404 | Programmable guardrails for LLM-based conversational systems |
| 9 | Giskard-AI/giskard-oss | 5,938 | Evaluation and testing library for LLM agents |

## What ours adds

- Fail-closed on missing acl: a chunk with no usable acl is a refusal, not a default allow.
- Hash-pinned chunks: the sha256 of every chunk text file must match the manifest, or the store is refused as tampered.
- A leak check at answer time: the final answer is compared with every chunk the tenant may not read, and the bound is printed beside the score.
- Orphan and mixed-model refusal: a retrieved id absent from the manifest, or a store with more than one embedding dimension, is refused.
- Mutation-tested: the suite must kill every seeded defect in the gate, and the runner prints the count.
