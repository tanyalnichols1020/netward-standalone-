"""
Net Ward -- proxy daemon entrypoint

    python -m netward --config /etc/netward/config.json

Loads operator config, seeds vendor patterns on first run, then
binds the capture loop and runs until interrupted.
Management commands (install-patterns, list-patterns, etc.) live in
netward/cli.py and are not part of this entrypoint.
"""
import argparse
import asyncio
import sys

from netward.operator_layer import load_config, validate_storage_permissions
from netward.capture import start_capture_loop


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="netward",
        description="Net Ward passive deception proxy",
        epilog="For pattern management: python netward/cli.py --help",
    )
    parser.add_argument(
        "--config",
        required=True,
        metavar="PATH",
        help="Operator config JSON (see example_config.json for a template)",
    )
    parser.add_argument(
        "--allow-permissive-db",
        action="store_true",
        help="Allow startup even when the Net Ward DB path is world-writable.",
    )
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        validate_storage_permissions(
            config,
            allow_permissive_db=args.allow_permissive_db,
        )
    except Exception as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        asyncio.run(start_capture_loop(config))
    except KeyboardInterrupt:
        pass  # clean exit on Ctrl-C / SIGINT


if __name__ == "__main__":
    main()
