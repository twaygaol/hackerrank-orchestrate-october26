# Usage and Cost Report

## Final full-dataset run

- Date: 2026-10-25
- Command: `py -3.13 code/main.py`
- Input: `dataset/deletion_requests.csv`
- Requests processed: 518
- Output: repository-root `output.csv`
- Measured wall-clock runtime: approximately 2.45 seconds (local Windows environment; measured with PowerShell `Measure-Command` on the final parser revision)
- Result: 518 output rows written; structural validation passed with zero errors.

## Model usage

This implementation uses deterministic Python parsing, identity matching, timestamp filtering, policy rules, and JSON/CSV serialization. No external LLM or VLM provider was called during the final full-dataset run.

| Metric | Final run |
|---|---:|
| Model providers | None |
| Model names | None |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated total model cost | USD $0.00 |
| Estimated model cost per request | USD $0.00 |

The token and cost figures are zero because no model API was used; they are not estimates of local CPU time or developer effort. Local evidence parsing includes CSV, JSON, logs, SQLite-compatible SQL snapshots, PDF text extraction through `pypdf`, and image-derived observations from `code/media_evidence.json`.

## Reproduction

Install the declared dependency and run the agent from the repository root:

```powershell
py -3.13 -m pip install -r code/requirements.txt
py -3.13 code/main.py
py -3.13 code/evaluation/main.py
```

The evaluation command compares the agent against the 32 public labeled examples, runs participant-created unit checks, and validates the full `output.csv` structure. Public sample accuracy is not a claim of hidden-set accuracy.
