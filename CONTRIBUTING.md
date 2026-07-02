# Contributing to QuantumSafe

Thanks for your interest in improving QuantumSafe!

## Development setup

```bash
git clone https://github.com/Danny-397/Quantum-Safe
cd Quantum-Safe
pip install -e .                       # the shared scanner package (CLI)
pip install -r backend/requirements.txt
pip install -r requirements-dev.txt    # pytest
```

Run the app locally (see [DEPLOYMENT.md](DEPLOYMENT.md)) or the full stack with
`docker compose up --build`.

## Tests

All changes should keep the suite green:

```bash
pytest -q
```

Please add tests for new detection rules or features:

- Detection rules → `tests/test_scanner.py`
- Scoring / recommendations → `tests/test_scorer.py`
- Output formats / suppression / exclude → `tests/test_features.py`
- API behavior → `tests/test_api.py`

## Adding a detection rule

1. Add a `Rule` to `RULES` in `cli/scanner.py` with a `family`, risk level, and a
   regex (use word boundaries to limit false positives). For Python precision,
   consider the AST engine in the same file.
2. Add a recommendation for the family in `cli/recommender.py`.
3. Add a test that proves it's detected and add a sample to `examples/` if useful.

## Style

- Match the surrounding code; keep functions small and documented.
- No new runtime dependencies in the CLI unless necessary (it stays lightweight).
- Run `pytest -q` before opening a PR. CI runs the suite on Python 3.11 and 3.12.

## Reporting security issues

Please follow [SECURITY.md](SECURITY.md) — do not open public issues for
vulnerabilities.
