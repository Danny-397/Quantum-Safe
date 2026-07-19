"""quantumsafe command-line interface.

Commands:
    quantumsafe scan --path ./project [--output report.json|report.html]
    quantumsafe scan --repo https://github.com/org/app
    quantumsafe version
    quantumsafe auth --key <api-key>
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from . import reporter
from .scanner import scan_path, scan_repo

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".quantumsafe")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")


# --------------------------------------------------------------------------- #
# auth — store API key linking the CLI to a dashboard account
# --------------------------------------------------------------------------- #


def _save_config(data: dict) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    try:
        os.chmod(CONFIG_PATH, 0o600)  # best-effort; no-op on some platforms
    except OSError:
        pass


def load_config() -> dict:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def cmd_auth(args: argparse.Namespace) -> int:
    key = args.key.strip()
    if not key:
        print("Error: --key must not be empty.", file=sys.stderr)
        return 2
    cfg = load_config()
    cfg["api_key"] = key
    if args.api_url:
        cfg["api_url"] = args.api_url.rstrip("/")
    _save_config(cfg)
    print(f"API key saved to {CONFIG_PATH}")
    print("The CLI is now linked to your QuantumSafe dashboard account.")
    return 0


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #


def cmd_scan(args: argparse.Namespace) -> int:
    if bool(args.path) == bool(args.repo):
        print("Error: provide exactly one of --path or --repo.", file=sys.stderr)
        return 2

    exclude = args.exclude or None
    scan_deps = not args.no_deps
    reachability = not args.no_rank
    try:
        if args.repo:
            target = args.repo
            findings = scan_repo(args.repo, exclude=exclude, taint=args.taint,
                                 scan_deps=scan_deps, reachability=reachability)
        else:
            target = os.path.abspath(args.path)
            findings = scan_path(args.path, exclude=exclude, taint=args.taint,
                                 scan_deps=scan_deps, reachability=reachability)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    report = reporter.build_report(findings, target)

    if args.output:
        name = args.output.lower()
        ext = os.path.splitext(name)[1]
        if name.endswith(".cbom.json") or name.endswith(".cdx.json"):
            content = reporter.to_cbom(report)
        elif ext == ".json":
            content = reporter.to_json(report)
        elif ext in (".html", ".htm"):
            content = reporter.to_html(report)
        elif ext == ".sarif":
            content = reporter.to_sarif(report)
        elif ext == ".svg":
            content = reporter.to_badge_svg(report)
        else:
            print("Error: --output must end in .json, .cbom.json, .html, .sarif, or .svg",
                  file=sys.stderr)
            return 2
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"Report written to {args.output}")
        # Also show the summary in the terminal for convenience.
        reporter.print_terminal(report)
    else:
        reporter.print_terminal(report)

    _maybe_sync(report, args.no_sync)

    # Non-zero exit on HIGH findings so the CLI is CI-friendly.
    return 1 if report["summary"]["high"] > 0 and args.fail_on_high else 0


def _maybe_sync(report: dict, no_sync: bool) -> None:
    """Upload the report to the linked dashboard (if `auth` was run with an API URL)."""
    if no_sync:
        return
    cfg = load_config()
    key, url = cfg.get("api_key"), cfg.get("api_url")
    if not key or not url:
        return  # not linked to a dashboard — nothing to do

    import json
    import urllib.error
    import urllib.request

    body = json.dumps({"report": report}).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/api/v1/scan/import",
        data=body,
        headers={"Content-Type": "application/json", "X-API-Key": key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            res = json.load(resp)
        print(f"Synced to dashboard: scan #{res.get('scan_id')} ({url})")
    except urllib.error.HTTPError as exc:
        print(f"Dashboard sync failed (HTTP {exc.code}). Re-run 'quantumsafe auth' "
              f"to reconnect.", file=sys.stderr)
    except Exception as exc:
        print(f"Dashboard sync skipped ({exc}).", file=sys.stderr)


# --------------------------------------------------------------------------- #
# version
# --------------------------------------------------------------------------- #


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"quantumsafe {__version__}")
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quantumsafe",
        description="Scan codebases for quantum-vulnerable cryptography.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a local path or GitHub repo.")
    p_scan.add_argument("--path", help="Local directory or file to scan.")
    p_scan.add_argument("--repo", help="Public GitHub repository URL to scan.")
    p_scan.add_argument("--output",
                        help="Write report to this file: .json, .cbom.json (CycloneDX CBOM), "
                             ".html, .sarif, or .svg (risk badge).")
    p_scan.add_argument("--exclude", action="append", metavar="GLOB",
                        help="Glob of paths to skip (repeatable), e.g. --exclude 'tests/*'.")
    p_scan.add_argument("--taint", action="store_true",
                        help="Also run interprocedural data-flow analysis to flag "
                             "quantum-vulnerable crypto reached through Python wrapper "
                             "functions, across files via a whole-program call graph "
                             "(experimental).")
    p_scan.add_argument("--no-deps", action="store_true",
                        help="Skip dependency scanning (manifests + lockfiles: "
                             "requirements.txt, package.json, go.mod, pom.xml, Gemfile, "
                             "pyproject.toml, package-lock.json, poetry.lock, go.sum, …). "
                             "Dependency scanning is on by default.")
    p_scan.add_argument("--no-rank", action="store_true",
                        help="Skip reachability ranking (on by default): labels each "
                             "source finding reachable / test-example / unreferenced so "
                             "exploitable findings sort above dead or example code.")
    p_scan.add_argument("--fail-on-high", action="store_true",
                        help="Exit with code 1 if any HIGH-risk finding is present (for CI).")
    p_scan.add_argument("--no-sync", action="store_true",
                        help="Don't upload results to your linked dashboard account.")
    p_scan.set_defaults(func=cmd_scan)

    p_version = sub.add_parser("version", help="Print the version.")
    p_version.set_defaults(func=cmd_version)

    p_auth = sub.add_parser("auth", help="Link the CLI to a dashboard account.")
    p_auth.add_argument("--key", required=True, help="API key from your dashboard Settings page.")
    p_auth.add_argument("--api-url", help="Override the dashboard API base URL.")
    p_auth.set_defaults(func=cmd_auth)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
