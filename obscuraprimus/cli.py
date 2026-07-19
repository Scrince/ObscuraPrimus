from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from .advanced_analysis import (
    analyze_path_isolated,
    anomaly_score,
    authenticode_status,
    byte_histogram,
    carving_preview,
    deobfuscate_script,
    entropy_timeline,
    export_case_bundle,
    export_timeline,
    fuzzy_hash,
    import_case_bundle,
    import_immutable_evidence,
    inspect_browser_artifact,
    inspect_raw_image,
    inspect_windows_artifact,
    onboarding_sample_case,
    scan_yara_details,
    search_case,
    validate_sigma_rule,
    validate_yara_rules,
    virtual_hex_page,
    write_example_plugin,
    write_report_template,
)
from .case_db import create_finding, dashboard as case_dashboard, search_fts, store_analysis_results, update_finding
from .file_analysis import (
    add_evidence,
    analyze_path,
    carve_embedded_files,
    compare_files,
    create_case,
    hex_preview,
    search_hex,
    sign_report,
    strip_jpeg_exif,
    virustotal_lookup,
    write_analysis_report,
)
from .forensics import scan_path, write_report
from .health import check_github_update, portable_health
from .plugins import available_plugins
from .stego_engine import EmbedOptions, StegoError, embed_file, estimate_capacity, extract_file


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except StegoError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="obscuraprimus", description="Portable steganography toolkit")
    subcommands = parser.add_subparsers(dest="command", required=True)

    embed = subcommands.add_parser("embed", help="Embed a secret file into a cover")
    embed.add_argument("--cover", required=True)
    embed.add_argument("--secret", required=True)
    embed.add_argument("--out", required=True)
    
    embed.add_argument(
        "--password-env",
        default="OBSCURAPRIMUS_PASSWORD",
        help="Environment variable for password when non-interactive (default: OBSCURAPRIMUS_PASSWORD)",
    )
    embed.add_argument("--stego-key", default="")
    embed.add_argument("--encryption", choices=["None", "AES-256-GCM", "XChaCha20-Poly1305"], default="None")
    embed.add_argument("--kdf", choices=["PBKDF2-HMAC-SHA256", "scrypt"], default="PBKDF2-HMAC-SHA256")
    embed.add_argument("--no-compress", action="store_true")
    embed.add_argument("--adaptive", action="store_true")
    embed.add_argument("--spread", action="store_true")
    embed.add_argument("--density", choices=["maximum", "balanced", "stealth"], default="maximum")
    embed.add_argument("--verify", action="store_true")

    extract = subcommands.add_parser("extract", help="Extract a hidden file from a cover")
    extract.add_argument("--cover", required=True)
    extract.add_argument("--out", required=True)
    extract.add_argument(
        "--password-env",
        default="OBSCURAPRIMUS_PASSWORD",
        help="Environment variable for password when non-interactive (default: OBSCURAPRIMUS_PASSWORD)",
    )
    extract.add_argument("--stego-key", default="")

    capacity = subcommands.add_parser("capacity", help="Show exact carrier capacity")
    capacity.add_argument("--cover", required=True)
    capacity.add_argument("--adaptive", action="store_true")
    capacity.add_argument("--spread", action="store_true")
    capacity.add_argument("--density", choices=["maximum", "balanced", "stealth"], default="maximum")

    scan = subcommands.add_parser("scan", help="Forensic scan files or folders")
    scan.add_argument("target")
    scan.add_argument(
        "--password-env",
        default="OBSCURAPRIMUS_PASSWORD",
        help="Environment variable for password when non-interactive (default: OBSCURAPRIMUS_PASSWORD)",
    )
    scan.add_argument("--stego-key", default="")
    scan.add_argument("--no-recursive", action="store_true")
    scan.add_argument("--csv", default="")
    scan.add_argument("--json", default="")

    analyze = subcommands.add_parser("analyze", help="Analyze files or folders")
    analyze.add_argument("target")
    analyze.add_argument("--profile", choices=["quick", "deep", "stego-focused", "malware-triage"], default="deep")
    analyze.add_argument("--no-recursive", action="store_true")
    analyze.add_argument("--report", default="")
    analyze.add_argument("--template", choices=["executive", "technical", "chain-of-custody", "stego-only", "malware-triage"], default="")
    analyze.add_argument("--sign-report", action="store_true")
    analyze.add_argument("--yara-rules", default="")
    analyze.add_argument("--case-dir", default="")

    hex_cmd = subcommands.add_parser("hex", help="Show a safe hex preview")
    hex_cmd.add_argument("file")
    hex_cmd.add_argument("--offset", type=lambda value: int(value, 0), default=0)
    hex_cmd.add_argument("--length", type=int, default=512)
    hex_cmd.add_argument("--search", default="")

    case = subcommands.add_parser("case", help="Create a case or add evidence")
    case.add_argument("case_dir")
    case.add_argument("--name", default="case")
    case.add_argument("--add", default="")
    case.add_argument("--import-immutable", default="")
    case.add_argument("--search", default="")
    case.add_argument("--sample", action="store_true")
    case.add_argument("--tag", action="append", default=[])
    case.add_argument("--notes", default="")
    case.add_argument("--dashboard", action="store_true")
    case.add_argument("--fts", default="")
    case.add_argument("--export-bundle", default="")
    case.add_argument("--import-bundle", default="")
    case.add_argument("--sign-bundle", action="store_true")
    case.add_argument("--finding", default="")
    case.add_argument("--finding-file", default="")
    case.add_argument("--finding-severity", default="medium")
    case.add_argument("--update-finding", type=int, default=0)
    case.add_argument("--status", default="")
    case.add_argument("--owner", default="")

    carve = subcommands.add_parser("carve", help="Carve embedded files by signature")
    carve.add_argument("file")
    carve.add_argument("--out", required=True)
    carve.add_argument("--preview", action="store_true")

    compare = subcommands.add_parser("compare", help="Compare two files")
    compare.add_argument("left")
    compare.add_argument("right")

    exif = subcommands.add_parser("exif-strip", help="Remove JPEG EXIF APP1 metadata")
    exif.add_argument("input")
    exif.add_argument("output")

    vt = subcommands.add_parser("vt", help="VirusTotal hash lookup")
    vt.add_argument("sha256")
    vt.add_argument("--api-key", default="")

    subcommands.add_parser("health", help="Portable mode health check")
    subcommands.add_parser("plugins", help="List analyzer plugins")
    update = subcommands.add_parser("update-check", help="Check latest GitHub release")
    update.add_argument("--repo", required=True)
    update.add_argument("--current", default="1.0.0")

    yara = subcommands.add_parser("yara", help="Validate rules or show match details")
    yara.add_argument("--rules", required=True)
    yara.add_argument("--target", default="")

    charts = subcommands.add_parser("charts", help="Emit chart data as JSON")
    charts.add_argument("file")
    charts.add_argument("--kind", choices=["entropy", "histogram", "hex-page"], default="entropy")
    charts.add_argument("--offset", type=lambda value: int(value, 0), default=0)

    artifact = subcommands.add_parser("artifact", help="Inspect forensic artifacts")
    artifact.add_argument("file")
    artifact.add_argument("--kind", choices=["raw", "browser", "windows"], default="browser")

    timeline = subcommands.add_parser("timeline", help="Normalize and export file timeline")
    timeline.add_argument("target")
    timeline.add_argument("--out", required=True)

    detect = subcommands.add_parser("detect", help="Run detection helpers")
    detect.add_argument("file")
    detect.add_argument("--kind", choices=["sigma", "fuzzy", "anomaly", "deobfuscate", "authenticode"], default="anomaly")

    sdk = subcommands.add_parser("plugin-sdk", help="Create an example analyzer plugin")
    sdk.add_argument("directory")
    sdk.add_argument("--name", default="example_plugin")

    args = parser.parse_args(argv)

    def resolve_password(required: bool) -> str:
        
        env_name = getattr(args, "password_env", "OBSCURAPRIMUS_PASSWORD") or "OBSCURAPRIMUS_PASSWORD"
        from_env = os.environ.get(env_name, "")
        if from_env:
            return from_env
        if not required and args.command == "scan":
            
            if sys.stdin.isatty():
                try:
                    return getpass.getpass("Password (leave empty if none): ")
                except (EOFError, KeyboardInterrupt):
                    return ""
            return ""
        if not sys.stdin.isatty():
            raise SystemExit(
                f"Error: password required but stdin is not a TTY. "
                f"Set the {env_name} environment variable for non-interactive use."
            )
        try:
            return getpass.getpass("Password: ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise SystemExit("Error: password entry cancelled.") from exc

    if args.command == "embed":
        password = ""
        if args.encryption != "None":
            password = resolve_password(required=True)
            if not password:
                raise SystemExit("Error: a password is required when encryption is enabled.")
        embed_file(
            args.cover,
            args.secret,
            args.out,
            EmbedOptions(
                compress=not args.no_compress,
                encryption=args.encryption,
                password=password,
                adaptive=args.adaptive,
                spread=args.spread,
                verify_after_embed=args.verify,
                stego_key=args.stego_key,
                kdf=args.kdf,
                density=args.density,
            ),
            _print_progress,
        )
        return 0
    if args.command == "extract":
        out = Path(args.out)
        password = resolve_password(required=True)
        extract_file(args.cover, str(out.parent), password, out.name, args.stego_key, _print_progress)
        return 0
    if args.command == "capacity":
        print(estimate_capacity(args.cover, args.adaptive, args.spread, args.density))
        return 0
    if args.command == "scan":
        password = resolve_password(required=False)
        findings = scan_path(args.target, password, recursive=not args.no_recursive, stego_key=args.stego_key)
        for finding in findings:
            print(f"{finding.status.upper():10} risk={finding.risk_score:3d} {finding.confidence:6} {finding.cover_type:4} {finding.path} - {finding.details}")
        if args.csv:
            write_report(findings, args.csv)
        if args.json:
            write_report(findings, args.json)
        return 0
    if args.command == "analyze":
        results = analyze_path_isolated(args.target, recursive=not args.no_recursive, profile=args.profile, yara_rules=args.yara_rules)
        for item in sorted(results, key=lambda result: result.risk_score, reverse=True):
            print(f"risk={item.risk_score:3d} {item.magic_type:22} {item.path} - {item.explanation}")
        if args.report:
            if args.template:
                write_report_template(results, args.report, args.template)
            else:
                write_analysis_report(results, args.report)
            if args.sign_report:
                signature = sign_report(args.report)
                if signature:
                    print(f"Signed report: {signature}")
        if args.case_dir:
            store_analysis_results(args.case_dir, results)
        return 0
    if args.command == "hex":
        if args.search:
            offsets = search_hex(args.file, args.search.encode("utf-8"))
            print("\n".join(hex(offset) for offset in offsets))
        else:
            print(hex_preview(args.file, args.offset, args.length))
        return 0
    if args.command == "case":
        root = create_case(args.case_dir, args.name)
        if args.dashboard:
            print(json.dumps(case_dashboard(root), indent=2, sort_keys=True))
            return 0
        if args.fts:
            print(json.dumps(search_fts(root, args.fts), indent=2, sort_keys=True))
            return 0
        if args.export_bundle:
            print(json.dumps(export_case_bundle(root, args.export_bundle, args.sign_bundle), indent=2, sort_keys=True))
            return 0
        if args.import_bundle:
            print(json.dumps(import_case_bundle(args.import_bundle, root), indent=2, sort_keys=True))
            return 0
        if args.finding:
            finding_id = create_finding(root, args.finding_file, args.finding, args.notes, args.finding_severity)
            print(json.dumps({"finding_id": finding_id}, indent=2))
            return 0
        if args.update_finding:
            updates = {}
            if args.status:
                updates["status"] = args.status
            if args.owner:
                updates["owner"] = args.owner
            update_finding(root, args.update_finding, **updates)
            print(json.dumps({"updated": args.update_finding}, indent=2))
            return 0
        if args.sample:
            print(onboarding_sample_case(root))
            return 0
        if args.search:
            print(json.dumps(search_case(root, args.search), indent=2, sort_keys=True))
            return 0
        if args.import_immutable:
            print(json.dumps(import_immutable_evidence(root, args.import_immutable, args.tag, args.notes), indent=2, sort_keys=True))
            return 0
        if args.add:
            entry = add_evidence(root, args.add, args.tag, args.notes)
            print(f"Added evidence: {entry['sha256']} {entry['path']}")
        else:
            print(root)
        return 0
    if args.command == "carve":
        if args.preview:
            print(json.dumps(carving_preview(args.file, args.out), indent=2, sort_keys=True))
        else:
            print(json.dumps(carve_embedded_files(args.file, args.out), indent=2, sort_keys=True))
        return 0
    if args.command == "compare":
        print(json.dumps(compare_files(args.left, args.right), indent=2, sort_keys=True))
        return 0
    if args.command == "exif-strip":
        strip_jpeg_exif(args.input, args.output)
        return 0
    if args.command == "vt":
        print(json.dumps(virustotal_lookup(args.sha256, args.api_key), indent=2, sort_keys=True))
        return 0
    if args.command == "health":
        print(json.dumps(portable_health(), indent=2, sort_keys=True))
        return 0
    if args.command == "plugins":
        for plugin in available_plugins():
            print(f"{plugin.name}: {', '.join(plugin.extensions)} - {plugin.description}")
        return 0
    if args.command == "update-check":
        print(json.dumps(check_github_update(args.repo, args.current), indent=2, sort_keys=True))
        return 0
    if args.command == "yara":
        if args.target:
            print(json.dumps([match.__dict__ for match in scan_yara_details(args.target, args.rules)], indent=2, sort_keys=True))
        else:
            print(json.dumps(validate_yara_rules(args.rules), indent=2, sort_keys=True))
        return 0
    if args.command == "charts":
        if args.kind == "histogram":
            print(json.dumps(byte_histogram(args.file)))
        elif args.kind == "hex-page":
            print(json.dumps(virtual_hex_page(args.file, args.offset), indent=2, sort_keys=True))
        else:
            print(json.dumps(entropy_timeline(args.file), indent=2, sort_keys=True))
        return 0
    if args.command == "artifact":
        if args.kind == "raw":
            result = inspect_raw_image(args.file)
        elif args.kind == "windows":
            result = inspect_windows_artifact(args.file)
        else:
            result = inspect_browser_artifact(args.file)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "timeline":
        from .advanced_analysis import normalize_timeline

        results = analyze_path_isolated(args.target)
        events = normalize_timeline(results)
        export_timeline(events, args.out)
        print(json.dumps({"events": len(events), "output": args.out}, indent=2, sort_keys=True))
        return 0
    if args.command == "detect":
        if args.kind == "sigma":
            print(json.dumps(validate_sigma_rule(args.file), indent=2, sort_keys=True))
        elif args.kind == "fuzzy":
            print(json.dumps(fuzzy_hash(args.file), indent=2, sort_keys=True))
        elif args.kind == "authenticode":
            print(json.dumps(authenticode_status(args.file), indent=2, sort_keys=True))
        elif args.kind == "deobfuscate":
            print(json.dumps(deobfuscate_script(args.file), indent=2, sort_keys=True))
        else:
            print(json.dumps(anomaly_score(args.file), indent=2, sort_keys=True))
        return 0
    if args.command == "plugin-sdk":
        print(json.dumps(write_example_plugin(args.directory, args.name), indent=2, sort_keys=True))
        return 0
    return 2


def _print_progress(value: int, message: str) -> None:
    print(f"[{value:3d}%] {message}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
