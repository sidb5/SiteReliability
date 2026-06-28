#!/usr/bin/env python3
"""
CLI: mint and register a new Watchdog API key for a tenant.

Usage:
    python scripts/generate_api_key.py \\
        --tenant-id <uuid> \\
        --user-id   <uuid> \\
        --name      "my-service-key" \\
        --scopes    ingest alerts:read \\
        --environment live

The plaintext key is printed ONCE and never stored. Copy it immediately.
"""
import argparse
import json
import sys
import os

# Ensure project root is importable regardless of CWD
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security import generate_api_key
from database import SessionLocal
from models.db import ApiKey, _uuid


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate and register a Watchdog API key"
    )
    parser.add_argument("--tenant-id", required=True, help="Tenant UUID")
    parser.add_argument("--user-id", required=True, help="Owning user UUID")
    parser.add_argument("--name", required=True, help="Human-readable key name")
    parser.add_argument(
        "--scopes",
        nargs="+",
        default=["ingest"],
        choices=["ingest", "alerts:read", "webhooks:manage", "sources:read"],
        help="Scopes to grant (default: ingest)",
    )
    parser.add_argument(
        "--environment",
        choices=["live", "test"],
        default="live",
        help="Key environment prefix (default: live)",
    )
    args = parser.parse_args()

    plaintext, key_hash = generate_api_key(args.environment)
    key_prefix = plaintext[:12]

    db = SessionLocal()
    try:
        key = ApiKey(
            id=_uuid(),
            tenant_id=args.tenant_id,
            user_id=args.user_id,
            name=args.name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            environment=args.environment,
            scopes=json.dumps(args.scopes),
        )
        db.add(key)
        db.commit()
        db.refresh(key)

        print()
        print("=" * 60)
        print("API Key Generated — save the value below. It will NOT be shown again.")
        print("=" * 60)
        print(f"Key ID       : {key.id}")
        print(f"Key Value    : {plaintext}")
        print(f"Prefix       : {key_prefix}")
        print(f"Scopes       : {args.scopes}")
        print(f"Environment  : {args.environment}")
        print(f"Tenant ID    : {args.tenant_id}")
        print("=" * 60)
        print()
    except Exception as exc:
        db.rollback()
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
