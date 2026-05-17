from __future__ import annotations

import argparse
import json
import secrets
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from .findings import Finding, ScanReport, SkippedFile
from .redaction import DEFAULT_REPLACEMENT, redact_text
from .rewrite import apply_rewrite_plan, build_rewrite_plan
from .scan import FileKind, classify_file, iter_scan_files, scan_file_report, scan_git_history, scan_path_report, scan_sqlite


def _print_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def _finding_to_dict(finding: object) -> dict[str, object]:
    return asdict(finding)


def _skipped_to_dict(skipped: object) -> dict[str, object]:
    return asdict(skipped)


def _print_scan_report(report: ScanReport, *, json_output: bool) -> None:
    rows = [_finding_to_dict(finding) for finding in report.findings]
    skipped_rows = [_skipped_to_dict(skipped) for skipped in report.skipped]
    if json_output:
        _print_json({"findings": rows, "skipped": skipped_rows})
        return

    if not rows and not skipped_rows:
        print("No findings.")
        return

    for row in rows:
        key = row.get("key") or "-"
        print(
            f"{row['category']}\t{row['path']}:{row['line']}\t"
            f"key={key}\tfingerprint={row['fingerprint']}"
        )

    for row in skipped_rows:
        size = row.get("size")
        size_text = f"\tsize={size}" if size is not None else ""
        print(f"skipped\t{row['path']}\treason={row['reason']}{size_text}")


def _scan_command(args: argparse.Namespace) -> int:
    target = Path(args.path)
    findings: list[Finding] = []
    skipped: list[SkippedFile] = []

    if target.is_file() and classify_file(target) == FileKind.SQLITE:
        report = scan_file_report(
            target,
            max_text_bytes=args.max_text_bytes,
            max_scan_bytes=args.max_scan_bytes,
        )
        skipped.extend(report.skipped)
        if not report.skipped:
            findings.extend(scan_sqlite(target))
    else:
        report = scan_path_report(
            target,
            excluded_paths=args.exclude,
            max_text_bytes=args.max_text_bytes,
            max_scan_bytes=args.max_scan_bytes,
        )
        findings.extend(report.findings)
        skipped.extend(report.skipped)

    if args.git_history:
        findings.extend(scan_git_history(target))

    report = ScanReport(tuple(sorted(set(findings))), tuple(sorted(set(skipped))))
    _print_scan_report(report, json_output=args.json)
    return 1 if args.fail_on_findings and findings else 0


def _category_label(category: str) -> str:
    return {
        "secret": "密钥/密码",
        "account": "账号/用户名",
        "network": "公网IP/网络地址",
    }.get(category, category)


def _location_label(finding: Finding) -> str:
    location = f"第{finding.line}行" if finding.line > 0 else "未知位置"
    if finding.key:
        return f"{location} {finding.key}"
    return location


def _print_audit_section(findings: list[Finding]) -> None:
    if not findings:
        print("否")
        return

    print("是")
    by_path: dict[str, list[Finding]] = {}
    for finding in findings:
        by_path.setdefault(finding.path, []).append(finding)

    for path in sorted(by_path):
        print(f"- {path}")
        for finding in sorted(by_path[path]):
            print(
                f"  - {_location_label(finding)}："
                f"{_category_label(finding.category)}，标识 {finding.fingerprint}"
            )


def _print_skipped_section(skipped: list[SkippedFile]) -> None:
    print("3、是否存在跳过文件")
    if not skipped:
        print("否")
        return

    print("是")
    for item in sorted(skipped):
        size_text = f"，大小 {item.size}" if item.size is not None else ""
        print(f"- {item.path}：{item.reason}{size_text}")


def _scan_workspace_for_audit(
    root: Path,
    *,
    salt: bytes,
    max_text_bytes: int,
    max_scan_bytes: int,
) -> ScanReport:
    path_report = scan_path_report(
        root,
        salt=salt,
        max_text_bytes=max_text_bytes,
        max_scan_bytes=max_scan_bytes,
    )
    findings: set[Finding] = set(path_report.findings)
    skipped: set[SkippedFile] = set(path_report.skipped)
    skipped_paths = {item.path for item in skipped}
    sqlite_paths = [root] if root.is_file() else list(iter_scan_files(root))

    for path in sqlite_paths:
        if classify_file(path) != FileKind.SQLITE:
            continue
        if path.as_posix() in skipped_paths:
            continue
        findings.update(scan_sqlite(path, salt=salt))

    return ScanReport(tuple(sorted(findings)), tuple(sorted(skipped)))


def _audit_command(args: argparse.Namespace) -> int:
    root = Path(args.path)
    audit_salt = secrets.token_bytes(32)
    workspace_report = _scan_workspace_for_audit(
        root,
        salt=audit_salt,
        max_text_bytes=args.max_text_bytes,
        max_scan_bytes=args.max_scan_bytes,
    )
    history_root = root.parent if root.is_file() else root
    history_findings = scan_git_history(history_root, salt=audit_salt)

    print("1、是否存在敏感信息")
    _print_audit_section(list(workspace_report.findings))
    print()
    print("2、敏感信息是否进入git提交")
    _print_audit_section(sorted(set(history_findings)))
    print()
    _print_skipped_section(list(workspace_report.skipped))
    return 0


def _redact_command(args: argparse.Namespace) -> int:
    print(redact_text(args.text, replacement=args.replacement))
    return 0


def _rewrite_command(args: argparse.Namespace) -> int:
    plan = build_rewrite_plan(
        args.path,
        replacement=args.replacement,
        remove=args.remove,
        max_text_bytes=args.max_text_bytes,
    )

    if args.json:
        _print_json(
            {
                "path": plan.path,
                "has_changes": plan.has_changes(),
                "changes": [asdict(change) for change in plan.changes],
            }
        )
    elif plan.has_changes():
        print(plan.diff(), end="" if plan.diff().endswith("\n") else "\n")
    else:
        print("No rewrite changes.")

    if not args.apply:
        return 0

    result = apply_rewrite_plan(plan, in_place=True, backup=args.backup)
    if args.json:
        _print_json(asdict(result))
    else:
        print(f"changed={result.changed}")
        if result.backup_path is not None:
            print(f"backup={result.backup_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-guard",
        description="Scan, redact, and rewrite secret-looking values safely.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory.")
    scan_parser.add_argument("path", help="File or directory to scan.")
    scan_parser.add_argument("--json", action="store_true", help="Output JSON findings.")
    scan_parser.add_argument(
        "--git-history",
        action="store_true",
        help="Also scan reachable Git history from the target path.",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Path to exclude. Can be used multiple times.",
    )
    scan_parser.add_argument(
        "--max-text-bytes",
        type=int,
        default=5 * 1024 * 1024,
        help="Maximum size for full text scans.",
    )
    scan_parser.add_argument(
        "--max-scan-bytes",
        type=int,
        default=512 * 1024 * 1024,
        help="Maximum size for any file scan before reporting it as skipped.",
    )
    scan_parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with status 1 when findings exist.",
    )
    scan_parser.set_defaults(func=_scan_command)

    audit_parser = subparsers.add_parser(
        "audit",
        help="Print a fixed two-section secret audit report.",
    )
    audit_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository path to audit. Defaults to the current directory.",
    )
    audit_parser.add_argument(
        "--max-text-bytes",
        type=int,
        default=5 * 1024 * 1024,
        help="Maximum size for full text scans.",
    )
    audit_parser.add_argument(
        "--max-scan-bytes",
        type=int,
        default=512 * 1024 * 1024,
        help="Maximum size for any file scan before reporting it as skipped.",
    )
    audit_parser.set_defaults(func=_audit_command)

    redact_parser = subparsers.add_parser("redact", help="Redact inline secret-looking text.")
    redact_parser.add_argument("text", help="Text to redact.")
    redact_parser.add_argument(
        "--replacement",
        default=DEFAULT_REPLACEMENT,
        help="Replacement text for redacted values.",
    )
    redact_parser.set_defaults(func=_redact_command)

    rewrite_parser = subparsers.add_parser("rewrite", help="Preview or apply file rewrites.")
    rewrite_parser.add_argument("path", help="Text file to rewrite.")
    rewrite_parser.add_argument("--json", action="store_true", help="Output JSON plan.")
    rewrite_parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the rewrite. Without this flag, only a dry-run preview is shown.",
    )
    rewrite_parser.add_argument(
        "--backup",
        action="store_true",
        help="Create a .bak file before applying changes.",
    )
    rewrite_parser.add_argument(
        "--remove",
        action="store_true",
        help="Remove matched sensitive values instead of replacing them.",
    )
    rewrite_parser.add_argument(
        "--replacement",
        default=DEFAULT_REPLACEMENT,
        help="Replacement text for matched values.",
    )
    rewrite_parser.add_argument(
        "--max-text-bytes",
        type=int,
        default=5 * 1024 * 1024,
        help="Maximum file size for rewrite planning.",
    )
    rewrite_parser.set_defaults(func=_rewrite_command)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 1
    except OSError as exc:
        print(f"secret-guard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
