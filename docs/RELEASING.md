# Releasing QuantumSafe

The steps to cut a release, publish to PyPI, and list the GitHub Action on the
Marketplace. Steps that need your credentials (PyPI token, GitHub UI) are marked
🔑 — run those yourself; everything else is scripted and reproducible.

## 0. Pre-flight (already done for 0.2.0)

- [x] Version bumped in `pyproject.toml` and `cli/__init__.py` (0.2.0).
- [x] `CHANGELOG.md` has a dated `[0.2.0]` section.
- [x] Full test suite green: `python -m pytest -q` (97 passing).
- [x] Benchmarks reproduce: `python benchmark/evaluate.py` (100% precision) and
      `python benchmark/seeded.py` (100% recall).

## 1. Build and validate the distribution

```bash
rm -rf dist build *.egg-info
python -m build            # produces dist/*.whl and dist/*.tar.gz
python -m twine check dist/*   # metadata must PASS
```

Sanity-check the artifact in a throwaway environment:

```bash
python -m venv /tmp/qsvenv
/tmp/qsvenv/bin/pip install dist/quantumsafe_scan-0.2.0-py3-none-any.whl
/tmp/qsvenv/bin/quantumsafe version     # -> quantumsafe 0.2.0
```

## 2. 🔑 Publish to PyPI

You need a PyPI API token (https://pypi.org/manage/account/token/). Test on
TestPyPI first if you like:

```bash
# optional dry run
python -m twine upload --repository testpypi dist/*

# real publish
python -m twine upload dist/*
```

`quantumsafe-scan` is already registered on PyPI (0.1.0 is live), so this uploads
0.2.0 as a new release. Verify: `pip install --upgrade quantumsafe-scan`.

## 3. 🔑 Tag and create the GitHub release

```bash
git tag -a v0.2.0 -m "QuantumSafe 0.2.0"
git push origin v0.2.0
```

Then on GitHub → **Releases → Draft a new release**, choose tag `v0.2.0`, title
"QuantumSafe 0.2.0", and paste the `[0.2.0]` section of `CHANGELOG.md` as the
notes.

## 4. 🔑 List the GitHub Action on the Marketplace

`action.yml` lives at the repo root with `name`, `description`, and `branding`
(shield / blue) — the fields the Marketplace requires. To list it:

1. Open the `v0.2.0` release draft (step 3).
2. Check **"Publish this Action to the GitHub Marketplace."**
3. Accept the agreement, pick a category (**Code quality** / **Security**), and
   publish.

Consumers then use it as:

```yaml
- uses: Danny-397/Quantum-Safe-Scan@v0.2.0
  with:
    path: .
    fail-on-high: "true"
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: quantumsafe.sarif
```

## 5. Post-release

- [ ] Confirm the PyPI page shows 0.2.0 and the README renders.
- [ ] Confirm `uses: Danny-397/Quantum-Safe-Scan@v0.2.0` resolves in a test repo.
- [ ] Move the `[0.2.0]` heading's link target if the tag URL changes.
