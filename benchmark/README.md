# Scanner evaluation benchmark

A labeled benchmark that measures how well the QuantumSafe scanner actually works
— so "it detects vulnerable crypto" is a *measured* claim, not an assertion.

## Run it

```bash
pip install -e .
python benchmark/evaluate.py
```

## Method

- **Ground truth** (`labels.json`) is defined at **(file, detection-family)**
  granularity by hand.
- `benchmark/positive/` contains known-vulnerable code; `benchmark/negative/`
  contains safe code and **decoys** designed to trip a naive matcher: crypto names
  that appear only in **comments, docstrings, log messages, and exception
  strings**, and **word-boundary traps** (`md5sumLabel`, `rc4legacyName`,
  `dsaCount`) that must *not* match.
- `evaluate.py` runs the real scanner **twice** — once as a naive line-level regex
  and once with the string/comment-aware pass — compares detected vs. expected
  pairs, and reports precision / recall / F1 **plus the exact false positives and
  false negatives**, so the numbers are auditable and the improvement is measured.

## Results (current)

18 files (10 positive, 8 negative/decoy) across 9 languages, 26 labeled findings:

| Configuration | TP | FP | FN | Precision | Recall | F1 |
|---|--:|--:|--:|--:|--:|--:|
| Naive line-regex baseline | 26 | 27 | 0 | 49.1% | 100% | 65.8% |
| **QuantumSafe (usage-aware)** | **26** | **0** | **0** | **100%** | **100%** | **100%** |

The usage-aware pass removes **27 false positives** — keyword mentions inside
docstrings, log/exception strings, trailing comments, and multi-line block
comments — without losing a true positive. Crucially, this now spans **all
supported languages**, not just Python: 13 of the removed false positives come
from Java, JavaScript, and Go decoys (`negative/notes.java`, `messages.js`,
`notes.go`). Genuine crypto usages whose algorithm is named *inside* a string
argument — e.g. Java's `getInstance("SHA-1")`, Node's
`createCipheriv("aes-128-gcm", …)` — are preserved by the string-argument
recovery pass, the cross-language analogue of the Python AST engine.

## Real-world benchmark (`realworld.py`)

`evaluate.py` measures **precision/recall** on a small labeled corpus.
`realworld.py` answers the complementary question — *what does the scanner find in
real production code?* — by downloading the latest sdist of 37 popular PyPI
packages from the PyPI JSON API, extracting each (nothing built or executed), and
running the scanner:

```bash
python benchmark/realworld.py            # curated 37-package set
python benchmark/realworld.py --limit 10 # first N only
python benchmark/realworld.py flask paramiko  # explicit packages
```

Latest run: **32 of 37** packages had findings across **10,938** Python files —
**5,512** findings (**4,083** HIGH-risk). Full results, per-package table, and
`file:line` examples in [RESULTS-realworld.md](RESULTS-realworld.md). Because these
are *unlabeled* real packages, results are reported as *discoveries* (each with
provenance), not scored against ground truth.

## Seeded recall benchmark (`seeded.py`)

The labeled corpus above is deliberately small, so on its own it measures
*precision* well but says little about *recall* at scale. `seeded.py` closes that
gap with a **mutation benchmark** whose ground truth is known **by
construction**: it embeds real quantum-vulnerable API calls (many idiomatic
variants per family, across 7 languages) into host files and asserts each is
detected, then embeds the *same algorithm name* only in a comment and a string
and asserts it is **not**.

```bash
python benchmark/seeded.py
```

Latest run: **50 seeded positive cases → 100% recall**, and **0 false positives**
across the 50 negative mutations (**100% mutation precision**). Per-language and
per-family recall tables, plus any misses, are written to
[RESULTS-seeded.md](RESULTS-seeded.md). This measures recall over API *variety*
(breadth), complementing the precision figure above; obfuscated wrapper chains
are a separate concern handled by the `--taint` data-flow engine.

## Honest limitations (what this benchmark does *not* prove)

This is a focused regression benchmark, not a large-scale field study. Real-world
caveats, stated plainly:

- **Labeled-corpus scale:** the precision corpus is 18 files / 26 findings. The
  seeded harness adds 50 constructed recall cases, but neither is a claim of 100%
  accuracy on arbitrary real-world code.
- **String/comment awareness spans all languages:** Python uses precise
  tokenizer-based masking; every other language uses a lexer-style state machine
  that blanks comment and string content. Go masks strings too, except on
  `import` lines (its import paths are the detection signal). Masked string usages
  are recovered by a targeted string-argument pass keyed on known crypto
  factories — precise, but narrower than a full parser, so an algorithm name
  passed through an *unrecognized* call can still be missed.
- **AST precision is still Python-only:** other languages remain pattern-based
  (regex + string-argument recovery), so deeply obfuscated wrappers may be missed
  (this is what the seeded harness's "misses" column and `--taint` address).

These are the genuine edges of a static pattern-based approach — see
`TECHNICAL_OVERVIEW.md` for how AST/Tree-sitter parsing would address them.
