#!/usr/bin/env python3
import argparse
import json
import os
import sys
import zipfile
from collections import defaultdict, Counter


def find_usage_info_members(zf: zipfile.ZipFile):
    for name in zf.namelist():
        if name.endswith('USAGE_INFO.json'):
            yield name


def iter_daily_activity(zf: zipfile.ZipFile, member: str):
    try:
        data = json.loads(zf.read(member).decode('utf-8', 'ignore'))
    except Exception:
        return
    da = (((data or {}).get('data') or {}).get('dailyActivity') or {})
    if not isinstance(da, dict):
        return
    for day, obj in da.items():
        yield day, obj or {}


def scan_bundles(data_dir: str, match_user: str | None = None):
    root = os.path.join(data_dir, 'diagnostics_bundles')
    users_counter = Counter()
    # hits structure: user -> zip_path -> member_path -> set(days)
    hits = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    if not os.path.exists(root):
        print(f"No diagnostics bundles folder found at {root}", file=sys.stderr)
        return users_counter, hits
    for server_id in sorted(os.listdir(root)):
        sdir = os.path.join(root, server_id)
        if not os.path.isdir(sdir):
            continue
        for fname in sorted(os.listdir(sdir)):
            if not fname.endswith('.zip'):
                continue
            path = os.path.join(sdir, fname)
            try:
                with zipfile.ZipFile(path, 'r') as z:
                    for member in find_usage_info_members(z):
                        for day, obj in iter_daily_activity(z, member):
                            users = (((obj.get('userLogin') or {}).get('users')) or [])
                            for u in users:
                                if isinstance(u, str):
                                    users_counter[u] += 1  # count active-days per user
                                    if match_user and match_user.lower() == u.lower():
                                        hits[u][path][member].add(day)
            except Exception as e:
                print(f"WARN: Failed to read {path}: {e}", file=sys.stderr)
                continue
    return users_counter, hits


def main():
    ap = argparse.ArgumentParser(description='Audit diagnostics bundles for user occurrences.')
    ap.add_argument('--data-dir', default=os.environ.get('DATA_DIR', os.path.abspath(os.path.join(os.path.dirname(__file__), 'lrmetrics_data'))), help='DATA_DIR path (default: env DATA_DIR or ./lrmetrics_data)')
    ap.add_argument('--user', help='Email/username to find')
    ap.add_argument('--list-users', action='store_true', help='List all users found with active-day counts')
    ap.add_argument('--top', type=int, default=50, help='Limit for list-users (default 50)')
    args = ap.parse_args()

    users_counter, hits = scan_bundles(args.data_dir, args.user)

    if args.list_users:
        print('Users (active-day counts):')
        for user, cnt in users_counter.most_common(args.top):
            print(f"  {user}: {cnt}")

    if args.user:
        if args.user not in hits:
            print(f"No occurrences found for {args.user}")
            return 0
        print(f"Occurrences for {args.user}:")
        for zpath, members in sorted(hits[args.user].items()):
            print(f"- ZIP: {zpath}")
            for member, days in sorted(members.items()):
                print(f"    member: {member}")
                for d in sorted(days):
                    print(f"      {d}")

    if not args.user and not args.list_users:
        ap.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
