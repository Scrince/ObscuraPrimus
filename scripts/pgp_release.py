from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from obscuraprimus.signing import ensure_release_key, export_public_key, make_config, release_fingerprint, sign_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage ObscuraPrimus release PGP signatures.")
    parser.add_argument("--gpg-exe", default="")
    parser.add_argument("--gpg-home", default="")
    parser.add_argument("--key-id", default="")
    subcommands = parser.add_subparsers(dest="command", required=True)

    ensure = subcommands.add_parser("ensure-key")
    ensure.add_argument("--public-key", required=True)

    fingerprint = subcommands.add_parser("fingerprint")

    sign = subcommands.add_parser("sign")
    sign.add_argument("artifact", nargs="+")

    args = parser.parse_args(argv)
    config = make_config(args.gpg_exe, args.gpg_home, args.key_id or None)
    if not config:
        print(json.dumps({"available": False, "error": "GPG was not found."}))
        return 2

    if args.command == "ensure-key":
        fpr = ensure_release_key(config)
        public_key = export_public_key(config, args.public_key)
        print(json.dumps({"available": True, "fingerprint": fpr, "public_key": str(public_key)}))
        return 0
    if args.command == "fingerprint":
        print(release_fingerprint(config))
        return 0
    if args.command == "sign":
        ensure_release_key(config)
        signatures = [str(sign_file(artifact, config)) for artifact in args.artifact]
        print(json.dumps({"available": True, "signatures": signatures}))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
