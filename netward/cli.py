"""
Net Ward -- Management CLI

Usage:
  netward --db PATH install-patterns [--force]
  netward --db PATH list-patterns
  netward --db PATH disable-pattern PATTERN_ID
  netward --db PATH enable-pattern  PATTERN_ID

--db defaults to netward.db in the current directory.
"""
from __future__ import annotations

import argparse
import sys
import time

from netward.storage import Storage
from netward import bootstrap as _bootstrap
from netward.regex_policy import PatternPolicyError


def _open_storage(args) -> Storage:
    return Storage(getattr(args, "db", "netward.db"))


def _cmd_install_patterns(args) -> None:
    storage = _open_storage(args)
    try:
        pats, mirrors = _bootstrap.install_vendor_patterns(storage, force=args.force)
        if pats == 0 and mirrors == 0 and not args.force:
            print("Vendor patterns already installed. Use --force to reinstall.")
        else:
            print(f"Installed {pats} pattern(s) and {mirrors} mirror response(s).")
    except _bootstrap.BootstrapError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except PatternPolicyError as exc:
        print(f"Error: pattern rejected by regex policy guard: {exc}", file=sys.stderr)
        sys.exit(2)
    finally:
        storage.close()


def _cmd_list_patterns(args) -> None:
    storage = _open_storage(args)
    try:
        patterns = storage.patterns_active()
        if not patterns:
            print("No active patterns.")
            return
        header = f"{'ID':<36}  {'KIND':<8}  {'ORIGIN':<8}  {'SEV':<8}  {'HITS':>6}  SIGNATURE"
        print(header)
        print("-" * len(header))
        for p in patterns:
            print(
                f"{p.get('id','?')[:36]:<36}  "
                f"{p.get('kind','?')[:8]:<8}  "
                f"{p.get('origin','?')[:8]:<8}  "
                f"{p.get('severity','?')[:8]:<8}  "
                f"{p.get('match_count',0):>6}  "
                f"{p.get('signature','?')[:60]}"
            )
    finally:
        storage.close()


def _cmd_disable_pattern(args) -> None:
    storage = _open_storage(args)
    try:
        rowcount = storage._conn.execute(
            "UPDATE patterns SET expires_at = ? WHERE id = ?",
            (time.time() - 1, args.pattern_id),
        ).rowcount
        if rowcount == 0:
            print(f"Pattern not found: {args.pattern_id}", file=sys.stderr)
            sys.exit(1)
        print(f"Pattern '{args.pattern_id}' disabled.")
    finally:
        storage.close()


def _cmd_enable_pattern(args) -> None:
    storage = _open_storage(args)
    try:
        rowcount = storage._conn.execute(
            "UPDATE patterns SET expires_at = NULL WHERE id = ?",
            (args.pattern_id,),
        ).rowcount
        if rowcount == 0:
            print(f"Pattern not found: {args.pattern_id}", file=sys.stderr)
            sys.exit(1)
        print(f"Pattern '{args.pattern_id}' enabled.")
    finally:
        storage.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="netward",
        description="Net Ward management CLI",
    )
    parser.add_argument(
        "--db",
        default="netward.db",
        metavar="PATH",
        help="Storage database path (default: netward.db)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_install = sub.add_parser("install-patterns", help="Seed vendor patterns into storage")
    p_install.add_argument("--force", action="store_true", help="Re-install even if already seeded")
    p_install.set_defaults(func=_cmd_install_patterns)

    p_list = sub.add_parser("list-patterns", help="List active patterns")
    p_list.set_defaults(func=_cmd_list_patterns)

    p_disable = sub.add_parser("disable-pattern", help="Disable a pattern by ID")
    p_disable.add_argument("pattern_id", help="Pattern ID to disable")
    p_disable.set_defaults(func=_cmd_disable_pattern)

    p_enable = sub.add_parser("enable-pattern", help="Re-enable a disabled pattern")
    p_enable.add_argument("pattern_id", help="Pattern ID to enable")
    p_enable.set_defaults(func=_cmd_enable_pattern)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
