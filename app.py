import os
import json
import hashlib
import zipfile
import io
import threading
import traceback
import uuid
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
)
import logging
import requests
from requests.auth import HTTPBasicAuth
from base64 import urlsafe_b64encode, urlsafe_b64decode
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret')

# Basic debug logging to stdout
logging.basicConfig(level=os.environ.get('LOG_LEVEL', 'INFO'))
app.logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))
app.logger.info('LRmetrics starting up')

DATA_DIR = os.environ.get('DATA_DIR', '/data')
os.makedirs(DATA_DIR, exist_ok=True)
CONFIG_PATH = os.path.join(DATA_DIR, 'servers.json')
PROGRESS_PATH = os.path.join(DATA_DIR, 'progress.json')
MASTER_PASSWORD_PATH = os.path.join(DATA_DIR, 'master_password.json')
JOBS_DIR = os.path.join(DATA_DIR, 'jobs')
ACTIVE_RETRIEVAL_PATH = os.path.join(DATA_DIR, 'active_retrieval_job')
os.makedirs(JOBS_DIR, exist_ok=True)


def _is_v2_request() -> bool:
    # v2 is now the default interface.
    v1_val = (request.args.get('v1') or '').strip().lower()
    if v1_val in ('1', 'true', 'yes', 'on'):
        return False
    val = (request.args.get('v2') or '').strip().lower()
    if val in ('0', 'false', 'no', 'off'):
        return False
    return True


def _with_v2_param(url: str) -> str:
    if not url or not url.startswith('/'):
        return url
    if 'v2=' in url:
        return url
    # Only preserve query param in explicit legacy mode.
    if _is_v2_request():
        return url
    sep = '&' if '?' in url else '?'
    return f"{url}{sep}v2=0"


@app.context_processor
def inject_v2_helpers():
    def v2_url(endpoint: str, **kwargs):
        return _with_v2_param(url_for(endpoint, **kwargs))

    def v2_path(path: str):
        return _with_v2_param(path)

    return {
        'is_v2': _is_v2_request(),
        'v2_mode_qs': ('' if _is_v2_request() else '?v2=0'),
        'v2_url': v2_url,
        'v2_path': v2_path,
    }


@app.after_request
def preserve_v2_on_redirects(response):
    # Keep v2 mode sticky during POST/redirect flows.
    try:
        if not _is_v2_request():
            return response
        if response.status_code in (301, 302, 303, 307, 308):
            loc = response.headers.get('Location') or ''
            if loc.startswith('/'):
                response.headers['Location'] = _with_v2_param(loc)
    except Exception:
        pass
    return response

@app.before_request
def require_master_password():
    # Allow unauthenticated access only to landing page, password set, logout, and static assets
    allowed_paths = {
        '/', '/set-password', '/logout'
    }
    if request.path.startswith('/static/'):
        return None
    if request.path in allowed_paths:
        return None
    if not session.get('LR_PWD'):
        app.logger.debug('Master password missing; redirecting from %s', request.path)
        flash('Please set the master password before using the app.', 'danger')
        return redirect(url_for('index'))


from flask import session
# Master password is now provided by user via landing page and stored in session
# Simple password-based protection helpers
def _key_bytes():
    pwd = session.get('LR_PWD') or ''
    return hashlib.sha256(pwd.encode()).digest()

def _master_hash(password: str, salt_hex: str) -> str:
    raw = bytes.fromhex(salt_hex) + (password or '').encode('utf-8')
    return hashlib.sha256(raw).hexdigest()

def _load_master_verifier():
    if not os.path.exists(MASTER_PASSWORD_PATH):
        return {}
    try:
        with open(MASTER_PASSWORD_PATH, 'r') as f:
            data = json.load(f) or {}
            if isinstance(data, dict):
                return data
    except Exception:
        app.logger.exception('Failed reading master password verifier')
    return {}

def _store_master_verifier(password: str):
    salt_hex = os.urandom(16).hex()
    payload = {'salt': salt_hex, 'hash': _master_hash(password, salt_hex)}
    with open(MASTER_PASSWORD_PATH, 'w') as f:
        json.dump(payload, f)

def _verify_master_password(password: str) -> bool:
    rec = _load_master_verifier()
    salt_hex = rec.get('salt') if isinstance(rec, dict) else None
    expected = rec.get('hash') if isinstance(rec, dict) else None
    if not (isinstance(salt_hex, str) and isinstance(expected, str) and salt_hex and expected):
        return False
    return _master_hash(password, salt_hex) == expected

def encrypt_password(plain: str) -> str:
    if plain is None:
        return ''
    if not session.get('LR_PWD'):
        raise RuntimeError('Master password not set')
    p = plain.encode()
    k = _key_bytes()
    x = bytes([b ^ k[i % len(k)] for i, b in enumerate(p)])
    return 'x:' + urlsafe_b64encode(x).decode()

def decrypt_password(stored: str) -> str:
    if not stored:
        return ''
    if isinstance(stored, str) and stored.startswith('x:'):
        if not session.get('LR_PWD'):
            raise RuntimeError('Master password not set')
        data = stored[2:]
        raw = urlsafe_b64decode(data)
        k = _key_bytes()
        p = bytes([b ^ k[i % len(k)] for i, b in enumerate(raw)])
        try:
            return p.decode()
        except Exception:
            return ''
    return stored

def _is_encrypted_unreadable(stored: str) -> bool:
    if not (isinstance(stored, str) and stored.startswith('x:')):
        return False
    if stored == 'x:':
        return False
    try:
        return decrypt_password(stored) == ''
    except Exception:
        return True

def _master_password_warning() -> str:
    # Non-blocking signal used by Setup/Retrieval pages.
    # Session remains valid even when stored credentials cannot be decrypted.
    if not session.get('LR_PWD'):
        return ''
    cfg = load_config()
    bad_lr = 0
    bad_gh = 0
    for s in (cfg.get('lightrun') or []):
        if _is_encrypted_unreadable(s.get('password') or ''):
            bad_lr += 1
    for r in (cfg.get('github') or []):
        if _is_encrypted_unreadable(r.get('token') or ''):
            bad_gh += 1
    if not (bad_lr or bad_gh):
        return ''
    parts = []
    if bad_lr:
        parts.append(f"{bad_lr} Lightrun credential set(s)")
    if bad_gh:
        parts.append(f"{bad_gh} GitHub token(s)")
    counts = ' and '.join(parts)
    return (
        f"Current master password cannot decrypt {counts}. "
        "Use the original master password, or re-enter credentials in Setup."
    )


def load_config():
    # config is a dict of source_type -> list of servers
    if not os.path.exists(CONFIG_PATH):
        app.logger.warning('Config file not found at %s', CONFIG_PATH)
        return {}
    with open(CONFIG_PATH, 'r') as f:
        try:
            c = json.load(f)
        except Exception:
            app.logger.exception('Failed to parse config file %s', CONFIG_PATH)
            return {}
    # do not perform format migrations; expect dict format
    app.logger.debug('Loaded config with keys: %s', list(c.keys()))
    return c


def save_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)
    app.logger.info('Config saved to %s; keys=%s', CONFIG_PATH, list(config.keys()))


def get_servers_for(src_type):
    config = load_config()
    servers = config.get(src_type, [])
    app.logger.debug('get_servers_for(%s): count=%d', src_type, len(servers))
    return servers


def set_servers_for(src_type, servers):
    # Remove transient auth flags before saving; store passwords (possibly encrypted)
    cleaned = []
    for s in servers:
        ss = dict(s)
        ss.pop('auth_ok', None)
        ss.pop('auth_checked', None)
        cleaned.append(ss)
    config = load_config()
    config[src_type] = cleaned
    save_config(config)
    app.logger.info('set_servers_for(%s): saved %d servers', src_type, len(cleaned))


def slugify(name: str) -> str:
    s = name.strip().lower()
    # keep alnum and dash
    s = ''.join([c if (c.isalnum() or c in '-_') else '-' for c in s])
    s = s.strip('-')
    if not s:
        s = 'srv'
    return s
    import re


def server_id_from_name(name: str, existing_ids=None) -> str:
    base = slugify(name)
    if existing_ids is None:
        existing_ids = []
    sid = base
    i = 1
    while sid in existing_ids:
        i += 1
        sid = f"{base}-{i}"
    return sid


from lightrun_api import (
    test_connection,
    authenticate as lr_authenticate,
    start_diagnostics as lr_start_diagnostics,
    poll_diagnostics_status as lr_poll_status,
    download_diagnostics as lr_download,
    diagnostics_request_body as lr_diag_body,
)
from github_api import (
    repo_exists as gh_repo_exists,
    list_commits as gh_list_commits,
    commit_details as gh_commit_details,
    store_report as gh_store_report,
    get_latest_report_generated_at as gh_latest_generated_at,
)
# Git CLI uploads
GIT_CLI_DIR = os.path.join(DATA_DIR, 'git_cli')
os.makedirs(GIT_CLI_DIR, exist_ok=True)

def store_git_cli_upload(repo_id: str, content: dict):
    rid = repo_id or 'manual'
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    rdir = os.path.join(GIT_CLI_DIR, rid)
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, f"{ts}.json"), 'w') as f:
        json.dump(content, f)

def iter_all_git_changes() -> list:
    # Collect changes from API reports and CLI uploads
    changes = []
    # API reports
    gh_root = os.path.join(DATA_DIR, 'github_reports')
    if os.path.exists(gh_root):
        for rid in os.listdir(gh_root):
            rdir = os.path.join(gh_root, rid)
            for f in os.listdir(rdir) if os.path.isdir(rdir) else []:
                if not f.endswith('.json'):
                    continue
                try:
                    with open(os.path.join(rdir, f), 'r') as fh:
                        rep = json.load(fh)
                    for c in (rep.get('changes') or []):
                        changes.append({'date': c.get('date'), 'files': c.get('files') or [], 'repo': rep.get('full_name'), 'source': 'api'})
                except Exception:
                    pass
    # CLI uploads
    if os.path.exists(GIT_CLI_DIR):
        for rid in os.listdir(GIT_CLI_DIR):
            rdir = os.path.join(GIT_CLI_DIR, rid)
            for f in os.listdir(rdir) if os.path.isdir(rdir) else []:
                if not f.endswith('.json'):
                    continue
                try:
                    with open(os.path.join(rdir, f), 'r') as fh:
                        rep = json.load(fh)
                    for c in (rep.get('changes') or []):
                        # Expect {commit, date, files[]}
                        changes.append({'date': c.get('date'), 'files': c.get('files') or [], 'repo': rep.get('repo') or rid, 'source': 'cli'})
                except Exception:
                    pass
    return changes

def parse_git_txt(stream) -> dict:
    # Parse plain text from `git log --name-only --date=iso --pretty="%H|%ad|%an"`
    changes = []
    current = None
    for raw in stream.read().decode('utf-8', errors='ignore').splitlines():
        line = raw.strip()
        if not line:
            continue
        if '|' in line:
            parts = line.split('|')
            if len(parts) >= 3:
                commit, date, author = parts[0], parts[1], parts[2]
                current = {'commit': commit, 'date': date, 'author': author, 'files': []}
                changes.append(current)
            continue
        # file path line
        if current is not None:
            current['files'].append(line)
    return {'changes': changes}

def build_correlations(audits_weeks: dict) -> list:
    # Build correlation entries: same-date same-file between audits and git changes
    git_changes = iter_all_git_changes()
    # index git by date->file set
    git_index = {}
    git_base_index = {}
    for ch in git_changes:
        d = (ch.get('date') or '')[:10]
        files = set([f for f in (ch.get('files') or []) if isinstance(f, str)])
        if not d or not files:
            continue
        entry = git_index.get(d) or set()
        entry.update(files)
        git_index[d] = entry
        # build basename -> full paths index per date
        bmap = git_base_index.get(d) or {}
        for fp in files:
            try:
                bn = os.path.basename(fp)
            except Exception:
                bn = fp
            paths = bmap.get(bn) or []
            if fp not in paths:
                paths.append(fp)
            bmap[bn] = paths
        git_base_index[d] = bmap
    correlations = []
    seen = set()
    ignored_users = {"system", "Agent", "Api Key"}
    for wk, wentry in (audits_weeks or {}).items():
        # iterate usersCounts is not needed; we need raw entries per day, but we only stored weekly counts.
        # Approximate: use actionCounts presence across week days by checking the audits entries again per stored files/dated entries in audits dir.
        # Simpler: Re-scan audits entries to match by day.
        try:
            # Collect audit entries for week from raw audits store
            week_start = wk
            from datetime import datetime, timedelta
            d0 = datetime.strptime(week_start, '%Y-%m-%d')
            days = [(d0 + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7)]
        except Exception:
            days = []
        # Scan raw audits for all servers
        for sid in os.listdir(AUDITS_DIR) if os.path.exists(AUDITS_DIR) else []:
            sdir = os.path.join(AUDITS_DIR, sid)
            if not os.path.isdir(sdir):
                continue
            for fname in os.listdir(sdir):
                if not fname.endswith('.json'):
                    continue
                try:
                    with open(os.path.join(sdir, fname), 'r') as fh:
                        payload = json.load(fh)
                    entries = payload.get('entries') or []
                except Exception:
                    entries = []
                for e in entries:
                    ct = (e.get('create_time') or '')[:10]
                    if ct not in days:
                        continue
                    file_name = e.get('file_name') or ''
                    if not file_name:
                        continue
                    # match file exact or basename
                    files_on_day = git_index.get(ct) or set()
                    chosen_path = None
                    if file_name in files_on_day:
                        chosen_path = file_name
                    else:
                        bn = os.path.basename(file_name)
                        cand = [p for p in files_on_day if os.path.basename(p) == bn]
                        if cand:
                            chosen_path = cand[0]
                        else:
                            chosen_path = (git_base_index.get(ct, {}).get(bn) or [None])[0]
                    if chosen_path:
                        usr = e.get('principal')
                        if usr in ignored_users:
                            continue
                        item = {
                            'date': ct,
                            'file': chosen_path,
                            'user': usr,
                            'action': e.get('action'),
                            'server': sid,
                            'week': wk,
                        }
                        key = (item['date'], item['file'], item['user'] or '', item['server'])
                        if key not in seen:
                            correlations.append(item)
                            seen.add(key)
    # Fallback attribution using diagnostics bundles usage summary when audits are missing
    try:
        with open(USAGE_SUMMARY_PATH, 'r') as f:
            usage_summary = json.load(f)
    except Exception:
        usage_summary = {}
    daily_by_server = usage_summary.get('daily_by_server') or {}
    for sid, dmap in daily_by_server.items():
        for dstr, entry in dmap.items():
            # Only count correlations where a filename from usage actionInsights matches a git filename (basename) on the same date
            if (entry.get('total') or 0) <= 0:
                continue
            git_files = git_index.get(dstr) or set()
            if not git_files:
                continue
            usage_files = set(entry.get('files') or [])
            if not usage_files:
                continue
            from os.path import basename
            git_basenames = set(basename(f) for f in git_files)
            usage_basenames = set(basename(f) for f in usage_files)
            matches = git_basenames.intersection(usage_basenames)
            if not matches:
                continue
            users = [u for u in (entry.get('users') or []) if u not in ignored_users]
            user = users[0] if users else None
            wk = _week_start(dstr)
            for bn in matches:
                # choose a full path from git for display, prefer first path found for that basename
                cand = [p for p in git_files if os.path.basename(p) == bn]
                chosen_path = cand[0] if cand else (git_base_index.get(dstr, {}).get(bn) or [bn])[0]
                if not user:
                    continue
                item = {
                    'date': dstr,
                    'file': chosen_path,
                    'user': user,
                    'action': 'USAGE',
                    'server': sid,
                    'week': wk,
                }
                key = (item['date'], item['file'], item['user'] or '', item['server'])
                if key not in seen:
                    correlations.append(item)
                    seen.add(key)
    # sort by date desc
    correlations.sort(key=lambda x: x.get('date',''), reverse=True)
    return correlations

def build_and_store_correlations_summary():
    # Build correlations for all servers and persist to summaries/correlations.json
    try:
        # Load audits summary to derive weeks map for 'all'
        audits_summary = {}
        try:
            with open(os.path.join(SUMMARIES_DIR, 'audits_summary.json'), 'r') as f:
                audits_summary = json.load(f)
        except Exception:
            audits_summary = {'weeks': {}}
        audits_weeks_all = (audits_summary.get('weeks') or {})
        corr_list = build_correlations(audits_weeks_all)
        # Group by week
        weeks = {}
        for c in corr_list:
            w = c.get('week')
            if not w:
                continue
            arr = weeks.get(w) or []
            arr.append(c)
            weeks[w] = arr
        out = {
            'generated_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'scope': 'all',
            'total': len(corr_list),
            'weeks': weeks,
        }
        os.makedirs(SUMMARIES_DIR, exist_ok=True)
        with open(os.path.join(SUMMARIES_DIR, 'correlations.json'), 'w') as f:
            json.dump(out, f, indent=2)
    except Exception:
        pass

def load_correlations_summary(selected_server: str = None, week_whitelist=None) -> list:
    # Read precomputed correlations from summaries/correlations.json so Display
    # can be reproduced without raw git/audits datasets.
    path = os.path.join(SUMMARIES_DIR, 'correlations.json')
    try:
        with open(path, 'r') as f:
            payload = json.load(f) or {}
    except Exception:
        return []
    weeks_map = payload.get('weeks') or {}
    week_set = set(week_whitelist or [])
    out = []
    for wk, arr in weeks_map.items():
        if week_set and wk not in week_set:
            continue
        for item in (arr or []):
            if selected_server and item.get('server') != selected_server:
                continue
            out.append(item)
    out.sort(key=lambda x: x.get('date', ''), reverse=True)
    return out
# Usage summary paths
SUMMARIES_DIR = os.path.join(DATA_DIR, 'summaries')
USAGE_SUMMARY_PATH = os.path.join(SUMMARIES_DIR, 'usage_summary.json')
os.makedirs(SUMMARIES_DIR, exist_ok=True)
SUMMARY_VERSION = 3

def _week_start(date_str: str) -> str:
    # Convert YYYY-MM-DD to Monday of that week, return as YYYY-MM-DD
    try:
        from datetime import datetime, timedelta
        d = datetime.strptime(date_str, '%Y-%m-%d')
        monday = d - timedelta(days=d.weekday())
        return monday.strftime('%Y-%m-%d')
    except Exception:
        return date_str

def build_usage_summary() -> dict:
    # Scan diagnostics bundles for USAGE_INFO.json and aggregate daily/weekly
    root = os.path.join(DATA_DIR, 'diagnostics_bundles')
    daily = {}
    daily_by_server = {}
    bundles_mtime_max = 0
    import zipfile
    from datetime import datetime
    for sid in os.listdir(root) if os.path.exists(root) else []:
        sdir = os.path.join(root, sid)
        if not os.path.isdir(sdir):
            continue
        if sid not in daily_by_server:
            daily_by_server[sid] = {}
        for f in os.listdir(sdir):
            if not f.endswith('.zip'):
                continue
            path = os.path.join(sdir, f)
            try:
                m = os.path.getmtime(path)
                if m > bundles_mtime_max:
                    bundles_mtime_max = m
                with zipfile.ZipFile(path, 'r') as z:
                    # robustly find USAGE_INFO.json anywhere within zip
                    target = next((name for name in z.namelist() if name.endswith('USAGE_INFO.json')), None)
                    if not target:
                        continue
                    with z.open(target) as zh:
                        content = zh.read().decode('utf-8', errors='ignore')
                    try:
                        j = json.loads(content)
                    except Exception:
                        continue
                    da = (((j or {}).get('data') or {}).get('dailyActivity') or {})
                    if not isinstance(da, dict):
                        continue
                    for dstr, obj in da.items():
                        actions = (obj.get('actionActivity') or {})
                        total = 0
                        if isinstance(actions, dict):
                            for k, v in actions.items():
                                try:
                                    total += int(v)
                                except Exception:
                                    pass
                        # attribute users from userLogin, but don't count userLogin itself as an action
                        users = []
                        ul = (((obj.get('userLogin') or {}).get('users')) or [])
                        if isinstance(ul, list):
                            users = [u for u in ul if isinstance(u, str)]
                        # collect file names affected from actionInsights; match filenames only (ignore paths)
                        files_set = set()
                        try:
                            insights = obj.get('actionInsights') or {}
                            def _collect_files(x):
                                try:
                                    import os as _os
                                    if isinstance(x, dict):
                                        for kk, vv in x.items():
                                            kkl = str(kk).lower()
                                            if isinstance(vv, str) and ('file' in kkl or kkl in ('filename','file_name')):
                                                files_set.add(_os.path.basename(vv))
                                            else:
                                                _collect_files(vv)
                                    elif isinstance(x, list):
                                        for it in x:
                                            _collect_files(it)
                                except Exception:
                                    pass
                            _collect_files(insights)
                        except Exception:
                            pass
                        # overall daily
                        entry = daily.get(dstr) or {'total': 0, 'users': set(), 'actionCounts': {}, 'files': set()}
                        entry['total'] += total
                        entry['users'].update(users)
                        entry['files'].update(files_set)
                        if isinstance(actions, dict):
                            ac = entry['actionCounts']
                            for k, v in actions.items():
                                try:
                                    ac[k] = ac.get(k, 0) + int(v)
                                except Exception:
                                    pass
                        daily[dstr] = entry
                        # per-server daily
                        sentry = daily_by_server[sid].get(dstr) or {'total': 0, 'users': set(), 'actionCounts': {}, 'files': set()}
                        sentry['total'] += total
                        sentry['users'].update(users)
                        sentry['files'].update(files_set)
                        if isinstance(actions, dict):
                            sac = sentry['actionCounts']
                            for k, v in actions.items():
                                try:
                                    sac[k] = sac.get(k, 0) + int(v)
                                except Exception:
                                    pass
                        daily_by_server[sid][dstr] = sentry
            except Exception:
                continue
    # convert sets to lists
    for dstr, entry in daily.items():
        entry['users'] = sorted(list(entry['users']))
        entry['files'] = sorted(list(entry.get('files') or []))
    for sid, dmap in daily_by_server.items():
        for dstr, entry in dmap.items():
            entry['users'] = sorted(list(entry['users']))
            entry['files'] = sorted(list(entry.get('files') or []))
    # weekly aggregation
    weeks = {}
    weeks_by_server = {}
    for dstr, entry in daily.items():
        w = _week_start(dstr)
        wentry = weeks.get(w) or {'total': 0, 'usersCounts': {}, 'actionCounts': {}}
        wentry['total'] += entry['total']
        users = entry.get('users', [])
        if len(users) == 1 and entry['total'] > 0:
            u = users[0]
            wentry['usersCounts'][u] = wentry['usersCounts'].get(u, 0) + entry['total']
        for k, v in (entry['actionCounts'] or {}).items():
            wentry['actionCounts'][k] = wentry['actionCounts'].get(k, 0) + v
        weeks[w] = wentry
    for sid, dmap in daily_by_server.items():
        smap = weeks_by_server.get(sid) or {}
        for dstr, entry in dmap.items():
            w = _week_start(dstr)
            wentry = smap.get(w) or {'total': 0, 'usersCounts': {}, 'actionCounts': {}}
            wentry['total'] += entry['total']
            users = entry.get('users', [])
            if len(users) == 1 and entry['total'] > 0:
                u = users[0]
                wentry['usersCounts'][u] = wentry['usersCounts'].get(u, 0) + entry['total']
            for k, v in (entry['actionCounts'] or {}).items():
                wentry['actionCounts'][k] = wentry['actionCounts'].get(k, 0) + v
            smap[w] = wentry
        weeks_by_server[sid] = smap
    summary = {
        'generated_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'daily': daily,
        'daily_by_server': daily_by_server,
        'weeks': weeks,
        'weeks_by_server': weeks_by_server,
        'bundles_mtime_max': bundles_mtime_max,
        'version': SUMMARY_VERSION,
    }
    try:
        with open(USAGE_SUMMARY_PATH, 'w') as f:
            json.dump(summary, f, indent=2)
    except Exception:
        pass
    return summary

# Audits fetching and attribution summary
AUDITS_DIR = os.path.join(DATA_DIR, 'audits')
os.makedirs(AUDITS_DIR, exist_ok=True)

def fetch_audits_for_server(server: dict, from_date: str, to_date: str, auth_cookie: dict, progress_cb=None) -> dict:
    s = requests.Session()
    s.verify = False
    # Get company id
    company_id = None
    try:
        resp = s.get(f"{server['url'].rstrip('/')}/api/account?withAccess=false", cookies=auth_cookie, verify=False)
        print(f"[LRmetrics][audits] /api/account status={resp.status_code}")
        company_id = (resp.json() or {}).get('companyName')
    except Exception as e:
        print(f"[LRmetrics][audits] Failed to fetch account: {e}")
        company_id = None
    if not company_id:
        return {'entries': [], 'fromDate': from_date, 'toDate': to_date}
    PAGE_SIZE = 1000
    page = 0
    entries = []
    while True:
        params = {"fromDate": from_date, "toDate": to_date, "size": PAGE_SIZE, "page": page}
        url = f"{server['url'].rstrip('/')}/management/company/{company_id}/audits"
        resp = s.get(url, params=params, cookies=auth_cookie, verify=False)
        print(f"[LRmetrics][audits] GET {url} page={page} status={resp.status_code}")
        try:
            audits = resp.json()
        except Exception:
            audits = []
        batch = 0
        for audit in audits:
            t = audit.get('type') or ''
            principal = audit.get('principal') or ''
            data = audit.get('data') or {}
            create_time = data.get('create_time') or audit.get('timestamp')
            file_name = data.get('file_name') or data.get('source')
            action = t.split(' ', 1)[0] if ' ' in t else t
            if action and principal:
                entries.append({
                    'principal': principal,
                    'action': action,
                    'file_name': file_name,
                    'create_time': create_time,
                })
                batch += 1
        if progress_cb:
            try:
                state = _read_progress_combined()
                lr_state = state.get('lightrun') or {}
                _write_progress(
                    'lightrun',
                    current=f"{server.get('name') or server.get('id')} · page {page}",
                    completed=lr_state.get('completed') or [],
                    total=lr_state.get('total') or 0,
                )
            except Exception:
                pass
        print(f"[LRmetrics][audits] Collected {batch} entries on page {page} (total so far {len(entries)}).")
        if not audits or len(audits) < PAGE_SIZE:
            break
        page += 1
    return {'entries': entries, 'fromDate': from_date, 'toDate': to_date}

def store_audits(server: dict, content: dict):
    sid = server.get('id') or server.get('name')
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    sdir = os.path.join(AUDITS_DIR, sid)
    os.makedirs(sdir, exist_ok=True)
    with open(os.path.join(sdir, f"{ts}.json"), 'w') as f:
        json.dump(content, f)

def build_audits_summary() -> dict:
    # Aggregate audits into weekly per-user totals and action type breakdown
    root = AUDITS_DIR
    weeks = {}
    weeks_by_server = {}
    allowed_actions = {"SNAPSHOT", "LOG", "COUNTER", "TICTOC"}
    ignored_users = {"system", "Agent", "Api Key"}
    for sid in os.listdir(root) if os.path.exists(root) else []:
        sdir = os.path.join(root, sid)
        if not os.path.isdir(sdir):
            continue
        smap = weeks_by_server.get(sid) or {}
        for f in os.listdir(sdir):
            if not f.endswith('.json'):
                continue
            path = os.path.join(sdir, f)
            try:
                with open(path, 'r') as fh:
                    payload = json.load(fh)
                entries = payload.get('entries') or []
            except Exception:
                entries = []
            for e in entries:
                ct = e.get('create_time') or ''
                try:
                    dstr = (ct[:10])
                except Exception:
                    continue
                # Filter by action type and user
                a = e.get('action') or ''
                if a not in allowed_actions:
                    continue
                u = e.get('principal') or ''
                if u in ignored_users:
                    continue
                w = _week_start(dstr)
                wentry = weeks.get(w) or {'total': 0, 'usersCounts': {}, 'actionCounts': {}}
                smentry = smap.get(w) or {'total': 0, 'usersCounts': {}, 'actionCounts': {}}
                wentry['total'] += 1
                smentry['total'] += 1
                if u:
                    wentry['usersCounts'][u] = wentry['usersCounts'].get(u, 0) + 1
                    smentry['usersCounts'][u] = smentry['usersCounts'].get(u, 0) + 1
                if a:
                    wentry['actionCounts'][a] = wentry['actionCounts'].get(a, 0) + 1
                    smentry['actionCounts'][a] = smentry['actionCounts'].get(a, 0) + 1
                weeks[w] = wentry
                smap[w] = smentry
        weeks_by_server[sid] = smap
    summary = {
        'generated_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'weeks': weeks,
        'weeks_by_server': weeks_by_server,
    }
    # Store audits summary alongside usage summary
    try:
        with open(os.path.join(SUMMARIES_DIR, 'audits_summary.json'), 'w') as f:
            json.dump(summary, f, indent=2)
    except Exception:
        pass
    return summary

def ensure_usage_summary_fresh():
    # Rebuild summary if missing or older than newest bundle
    latest_bundle_mtime = 0
    root = os.path.join(DATA_DIR, 'diagnostics_bundles')
    for sid in os.listdir(root) if os.path.exists(root) else []:
        sdir = os.path.join(root, sid)
        if not os.path.isdir(sdir):
            continue
        for f in os.listdir(sdir):
            if f.endswith('.zip'):
                try:
                    m = os.path.getmtime(os.path.join(sdir, f))
                    if m > latest_bundle_mtime:
                        latest_bundle_mtime = m
                except Exception:
                    continue
    current_mtime = -1
    try:
        if os.path.exists(USAGE_SUMMARY_PATH):
            current_mtime = os.path.getmtime(USAGE_SUMMARY_PATH)
    except Exception:
        current_mtime = -1
    needs_rebuild = current_mtime < latest_bundle_mtime
    # also rebuild if version mismatch
    try:
        if os.path.exists(USAGE_SUMMARY_PATH):
            with open(USAGE_SUMMARY_PATH, 'r') as f:
                cur = json.load(f)
            if (cur or {}).get('version') != SUMMARY_VERSION:
                needs_rebuild = True
    except Exception:
        needs_rebuild = True
    if needs_rebuild:
        build_usage_summary()

def ensure_audits_summary_fresh():
    # Rebuild audits summary if missing or older than newest audits file
    latest_audit_mtime = 0
    root = AUDITS_DIR
    for sid in os.listdir(root) if os.path.exists(root) else []:
        sdir = os.path.join(root, sid)
        if not os.path.isdir(sdir):
            continue
        for f in os.listdir(sdir):
            if f.endswith('.json'):
                try:
                    m = os.path.getmtime(os.path.join(sdir, f))
                    if m > latest_audit_mtime:
                        latest_audit_mtime = m
                except Exception:
                    continue
    current_mtime = -1
    audits_path = os.path.join(SUMMARIES_DIR, 'audits_summary.json')
    try:
        if os.path.exists(audits_path):
            current_mtime = os.path.getmtime(audits_path)
    except Exception:
        current_mtime = -1
    needs_rebuild = (not os.path.exists(audits_path)) or (current_mtime < latest_audit_mtime)
    if needs_rebuild:
        try:
            build_audits_summary()
        except Exception:
            pass

def store_retrieved(server, content, ts=None):
    sid = server.get('id')
    sdir = os.path.join(DATA_DIR, sid)
    os.makedirs(sdir, exist_ok=True)
    if ts is None:
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    fname = os.path.join(sdir, f"{ts}.json")
    with open(fname, 'w') as f:
        # try to write JSON prettified if possible
        try:
            j = json.loads(content)
            json.dump(j, f, indent=2)
        except Exception:
            f.write(content)
    return fname


def store_diagnostics_zip(server, content_bytes, ts=None):
    sid = server.get('id')
    sdir = os.path.join(DATA_DIR, 'diagnostics_bundles', sid)
    os.makedirs(sdir, exist_ok=True)
    if ts is None:
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    fname = os.path.join(sdir, f"{ts}.zip")
    with open(fname, 'wb') as f:
        f.write(content_bytes)
    return fname


def get_last_retrieved_timestamp():
    # find newest file mtime under DATA_DIR
    latest_ts = None
    for entry in os.listdir(DATA_DIR):
        sdir = os.path.join(DATA_DIR, entry)
        if not os.path.isdir(sdir):
            continue
        for fname in os.listdir(sdir):
            fpath = os.path.join(sdir, fname)
            try:
                m = os.path.getmtime(fpath)
            except Exception:
                continue
            if latest_ts is None or m > latest_ts:
                latest_ts = m
    if latest_ts is None:
        return None
    # return formatted local timestamp
    return datetime.fromtimestamp(latest_ts).strftime('%Y-%m-%d %H:%M:%S')

def _write_progress(source: str, current: str = '', completed=None, total: int = 0):
    # Merge per-source progress into a single JSON object
    try:
        if completed is None:
            completed = []
        entry = {
            'current': current,
            'completed': completed,
            'total': total,
            'ts': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        combined = {}
        try:
            if os.path.exists(PROGRESS_PATH):
                with open(PROGRESS_PATH, 'r') as f:
                    combined = json.load(f) or {}
        except Exception:
            combined = {}
        combined[source] = entry
        with open(PROGRESS_PATH, 'w') as f:
            json.dump(combined, f)
    except Exception:
        pass

def _clear_progress():
    try:
        if os.path.exists(PROGRESS_PATH):
            os.remove(PROGRESS_PATH)
    except Exception:
        pass

def _job_path(job_id: str) -> str:
    return os.path.join(JOBS_DIR, f"{job_id}.json")

def _utc_now_iso() -> str:
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

def _write_json_atomic(path: str, payload):
    tmp = f"{path}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    with open(tmp, 'w') as f:
        json.dump(payload, f)
    os.replace(tmp, path)

def _read_job(job_id: str):
    if not job_id:
        return None
    path = _job_path(job_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return None

def _write_job(job_id: str, payload):
    _write_json_atomic(_job_path(job_id), payload)

def _update_job(job_id: str, **fields):
    cur = _read_job(job_id) or {'job_id': job_id}
    cur.update(fields)
    _write_job(job_id, cur)

def _read_active_job_id():
    if not os.path.exists(ACTIVE_RETRIEVAL_PATH):
        return ''
    try:
        with open(ACTIVE_RETRIEVAL_PATH, 'r') as f:
            return (f.read() or '').strip()
    except Exception:
        return ''

def _acquire_active_job(job_id: str):
    try:
        fd = os.open(ACTIVE_RETRIEVAL_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            os.write(fd, job_id.encode('utf-8'))
        finally:
            os.close(fd)
        return True, ''
    except FileExistsError:
        existing = _read_active_job_id()
        existing_job = _read_job(existing) if existing else None
        if existing_job and existing_job.get('state') in ('completed', 'failed'):
            _release_active_job(existing)
            try:
                fd = os.open(ACTIVE_RETRIEVAL_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                try:
                    os.write(fd, job_id.encode('utf-8'))
                finally:
                    os.close(fd)
                return True, ''
            except Exception:
                pass
        return False, existing

def _release_active_job(job_id: str):
    try:
        current = _read_active_job_id()
        if current == job_id and os.path.exists(ACTIVE_RETRIEVAL_PATH):
            os.remove(ACTIVE_RETRIEVAL_PATH)
    except Exception:
        pass

def _read_progress_combined():
    try:
        if not os.path.exists(PROGRESS_PATH):
            return {}
        with open(PROGRESS_PATH, 'r') as f:
            return json.load(f) or {}
    except Exception:
        return {}

def _progress_snapshot():
    all_state = _read_progress_combined()
    lr = all_state.get('lightrun') or {}
    gh = all_state.get('github') or {}
    completed_sum = len(lr.get('completed') or []) + len(gh.get('completed') or [])
    current_name = ''
    phase_label = ''
    if lr.get('current'):
        current_name = lr.get('current')
        phase_label = 'Lightrun'
    elif gh.get('current'):
        current_name = gh.get('current')
        phase_label = 'GitHub'
    total = lr.get('total') or gh.get('total') or 0
    return {
        'total': total,
        'completed': completed_sum,
        'current': current_name,
        'phase': phase_label,
        'raw': all_state,
    }

@app.route('/progress')
def progress_all():
    # Return combined progress for all sources
    try:
        if not os.path.exists(PROGRESS_PATH):
            return jsonify({}), 200
        with open(PROGRESS_PATH, 'r') as f:
            state = json.load(f)
        return jsonify(state), 200
    except Exception:
        return jsonify({}), 200

@app.route('/progress/<source>')
def progress(source):
    # Back-compat endpoint: return only the requested source's progress
    try:
        if not os.path.exists(PROGRESS_PATH):
            return jsonify({'current': '', 'completed': [], 'total': 0}), 200
        with open(PROGRESS_PATH, 'r') as f:
            combined = json.load(f) or {}
        entry = combined.get(source) or {'current': '', 'completed': [], 'total': 0}
        return jsonify(entry), 200
    except Exception:
        return jsonify({'current': '', 'completed': [], 'total': 0}), 200


@app.route('/')
def index():
    last = get_last_retrieved_timestamp()
    has_pwd = bool(session.get('LR_PWD'))
    app.logger.debug('Index: has_pwd=%s last=%s', has_pwd, last)
    return render_template('index.html', last_retrieved=last, has_pwd=has_pwd)


@app.route('/set-password', methods=['POST'])
def set_password():
    pwd = request.form.get('master_password', '').strip()
    if not pwd:
        flash('Please enter a password', 'danger')
        return redirect(url_for('index'))
    verifier = _load_master_verifier()
    if verifier:
        if not _verify_master_password(pwd):
            session.pop('LR_PWD', None)
            flash('Incorrect master password. Use the original password for this data set.', 'danger')
            return redirect(url_for('index'))
    else:
        # First initialization for this DATA_DIR. This locks future sessions to the same password.
        _store_master_verifier(pwd)
        app.logger.info('Master password verifier initialized at %s', MASTER_PASSWORD_PATH)
    session['LR_PWD'] = pwd
    flash('Password set', 'success')
    return redirect(url_for('display'))


@app.route('/logout')
def logout():
    session.pop('LR_PWD', None)
    flash('Password cleared. Set it again to continue.', 'info')
    return redirect(url_for('index'))


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    src = request.args.get('src', 'lightrun')
    servers = get_servers_for(src)
    app.logger.debug('Setup GET: src=%s servers_count=%d', src, len(servers))
    if request.method == 'POST':
        app.logger.debug('Setup POST: src=%s form_keys=%s', src, list(request.form.keys()))
        if not session.get('LR_PWD'):
            flash('Set the master password on the home page before saving.', 'danger')
            return redirect(url_for('setup', src=src))
        if src == 'lightrun':
            # creation of a new Lightrun server
            name = request.form.get('name')
            url = request.form.get('url')
            email = request.form.get('email')
            password = request.form.get('password')
            if not name or not url or not email:
                flash('Name, URL and Email are required', 'danger')
                return redirect(url_for('setup', src=src))
            existing_ids = [s.get('id') for s in servers]
            sid = server_id_from_name(name, existing_ids)
            server = {'id': sid, 'name': name, 'url': url.rstrip('/'), 'email': email, 'password': password}
            # Test connectivity and auth
            ok, status, info = test_connection({'id': sid, 'name': name, 'url': url.rstrip('/'), 'email': email, 'password': password})
            if not ok:
                flash(f'Connection test failed: {info}', 'danger')
                return redirect(url_for('setup', src=src))
            if isinstance(info, dict):
                auth = info.get('auth') or {}
                if not auth.get('ok'):
                    diag = auth.get('diag') or {}
                    detail = f"status={diag.get('status')} url={diag.get('url')}"
                    body = diag.get('body')
                    if isinstance(body, str):
                        detail += f" body_snippet={body[:120]}"
                    elif isinstance(body, dict):
                        detail += f" body_keys={list(body.keys())}"
                    flash(f'Authentication failed — server not saved ({detail})', 'danger')
                    return redirect(url_for('setup', src=src))
            server['password'] = encrypt_password(password)
            servers.append(server)
            set_servers_for(src, servers)
            if isinstance(info, dict):
                ver = info.get('version')
                if ver:
                    server['version'] = ver
            set_servers_for(src, servers)
            flash('Server saved', 'success')
            return redirect(url_for('setup', src=src))
        elif src == 'github':
            # creation of a new GitHub repository config
            name = request.form.get('name', '').strip()
            full_name = request.form.get('full_name', '').strip()  # owner/repo
            token = request.form.get('token', '')
            api_base = (request.form.get('api_base') or '').strip()
            if not name or not full_name:
                flash('Name and Repository (owner/repo) are required', 'danger')
                return redirect(url_for('setup', src=src))
            ok, status, info = gh_repo_exists(full_name, token, api_base or None)
            app.logger.debug('GitHub repo_exists: ok=%s status=%s info_keys=%s', ok, status, (list(info.keys()) if isinstance(info, dict) else 'text'))
            if not ok:
                snippet = ''
                try:
                    snippet = (info if isinstance(info, str) else str(info))[:160]
                except Exception:
                    snippet = ''
                flash(f'Repository validation failed (status {status}). {snippet}', 'danger')
                return redirect(url_for('setup', src=src))
            existing_ids = [s.get('id') for s in servers]
            sid = server_id_from_name(name, existing_ids)
            repo = {'id': sid, 'name': name, 'full_name': full_name, 'api_base': api_base}
            repo['token'] = encrypt_password(token) if token else ''
            servers.append(repo)
            set_servers_for(src, servers)
            flash('Repository saved', 'success')
            return redirect(url_for('setup', src=src))
        else:
            flash(f'Source {src} is not supported yet.', 'warning')
            return redirect(url_for('setup', src=src))
    return render_template('setup.html', src=src, servers=servers, master_password_warning=_master_password_warning())


@app.route('/setup/test/<src>/<server_id>')
def setup_test(src, server_id):
    servers = get_servers_for(src)
    s = next((x for x in servers if x.get('id') == server_id), None)
    if not s:
        return jsonify({'ok': False, 'error': 'server not found'}), 404
    # use stored password (decrypt for test)
    s_for_test = s.copy()
    s_for_test['password'] = decrypt_password(s.get('password')) or ''
    ok, status, info = test_connection(s_for_test)
    # if ok, store version into server record
    if ok:
        # info may be a dict with version and auth
        if isinstance(info, dict):
            ver = info.get('version')
            if ver:
                s['version'] = ver
        set_servers_for(src, servers)
        return jsonify({'ok': True, 'status': status, 'info': info})
    return jsonify({'ok': False, 'status': status, 'info': info})


@app.route('/setup/test-params/<src>', methods=['POST'])
def setup_test_params(src):
    # test connection details provided in the request without saving
    # support both form-encoded and JSON bodies
    data = {}
    if request.content_type and 'application/json' in request.content_type:
        data = request.get_json(silent=True) or {}
    else:
        # Flask's request.form is an ImmutableMultiDict
        data = request.form.to_dict()

    if src == 'github':
        full_name = (data.get('full_name') or '').strip()
        token = (data.get('token') or '').strip()
        api_base = (data.get('api_base') or '').strip() or None
        if not full_name:
            return jsonify({'ok': False, 'error': 'repository (owner/repo) missing'}), 400
        ok, status, info = gh_repo_exists(full_name, token, api_base)
        return jsonify({'ok': ok, 'status': status, 'info': info if ok else info}), (200 if ok else (status or 500))

    url = (data.get('url') or data.get('server_url') or '').strip()
    email = (data.get('email') or data.get('username') or '').strip()
    password = (data.get('password') or data.get('pwd') or '')
    # If testing from edit view with blank password, fall back to stored decrypted password
    if not password:
        server_id = data.get('server_id') or data.get('id') or ''
        if server_id:
            servers = get_servers_for(src)
            s = next((x for x in servers if x.get('id') == server_id), None)
            if s:
                password = decrypt_password(s.get('password')) or ''
        # If server_id wasn't provided, try to match by URL/email to find existing server
        if not password:
            servers = get_servers_for(src)
            match = next((x for x in servers if (x.get('url') == url and (email == '' or x.get('email') == email))), None)
            if match:
                password = decrypt_password(match.get('password')) or ''
    if not url:
        app.logger.debug('setup_test_params called without url; form=%s json=%s', dict(request.form), request.get_data(as_text=True))
        return jsonify({'ok': False, 'error': 'url missing'}), 400
    server = {'url': url, 'email': email or '', 'password': password or ''}
    ok, status, info = test_connection(server)
    if ok:
        # info is dict with version and auth
        if isinstance(info, dict):
            return jsonify({'ok': True, 'status': status, 'version': info.get('version'), 'auth': info.get('auth')})
        return jsonify({'ok': True, 'status': status, 'version': info})
    return jsonify({'ok': False, 'status': status, 'info': info})


@app.route('/setup/edit/<src>/<server_id>', methods=['GET', 'POST'])
def setup_edit(src, server_id):
    servers = get_servers_for(src)
    s = next((x for x in servers if x.get('id') == server_id), None)
    if not s:
        flash('Server not found', 'danger')
        return redirect(url_for('setup', src=src))
    if request.method == 'POST':
        if not session.get('LR_PWD'):
            flash('Set the master password on the home page before updating servers.', 'danger')
            return redirect(url_for('setup_edit', src=src, server_id=server_id))
        # update fields; if password left blank, keep existing
        name = request.form.get('name')
        url = request.form.get('url')
        email = request.form.get('email')
        password = request.form.get('password')
        if not name or not url or not email:
            flash('Name, URL and Email are required', 'danger')
            return redirect(url_for('setup_edit', src=src, server_id=server_id))
        # determine plaintext password for test
        if password:
            plain_pwd = password
        else:
            plain_pwd = decrypt_password(s.get('password'))

        s_for_test = {'id': s.get('id'), 'name': name, 'url': url.rstrip('/'), 'email': email, 'password': plain_pwd}
        ok, status, info = test_connection(s_for_test)
        if not ok:
            flash(f'Connection test failed: {info}', 'danger')
            return redirect(url_for('setup_edit', src=src, server_id=server_id))
        if isinstance(info, dict):
            auth = info.get('auth') or {}
            if not auth.get('ok'):
                diag = auth.get('diag') or {}
                detail = f"status={diag.get('status')} url={diag.get('url')}"
                body = diag.get('body')
                if isinstance(body, str):
                    detail += f" body_snippet={body[:120]}"
                elif isinstance(body, dict):
                    detail += f" body_keys={list(body.keys())}"
                flash(f'Authentication failed — changes not saved ({detail})', 'danger')
                return redirect(url_for('setup_edit', src=src, server_id=server_id))

        s['name'] = name
        s['url'] = url.rstrip('/')
        s['email'] = email
        if password:
            s['password'] = encrypt_password(password)
        # leave existing password if password field blank
        # update saved metadata (only store version; do not persist auth flags)
        if isinstance(info, dict):
            ver = info.get('version')
            if ver:
                s['version'] = ver

        set_servers_for(src, servers)
        flash('Server updated', 'success')
        return redirect(url_for('setup', src=src))
    # render edit form (password not populated)
    return render_template('setup_edit.html', src=src, server=s, master_password_warning=_master_password_warning())


@app.route('/setup/delete/<src>/<server_id>', methods=['POST'])
def setup_delete(src, server_id):
    servers = get_servers_for(src)
    new = [x for x in servers if x.get('id') != server_id]
    set_servers_for(src, new)
    flash('Server removed', 'info')
    return redirect(url_for('setup', src=src))


@app.route('/upload/git', methods=['POST'])
def upload_git_cli():
    # Accept a JSON file containing {repo: string, changes: [{commit, date, author, files: [..]}]}
    try:
        repo_id = request.form.get('repo_id') or 'manual'
        if 'file' not in request.files:
            flash('No file uploaded', 'warning')
            return redirect(url_for('retrieve'))
        f = request.files['file']
        data = json.load(f.stream)
        if not isinstance(data, dict):
            flash('Invalid JSON format', 'danger')
            return redirect(url_for('retrieve'))
        store_git_cli_upload(repo_id, data)
        # Rebuild correlations summary after new git data arrives
        try:
            ensure_audits_summary_fresh()
            build_and_store_correlations_summary()
        except Exception:
            pass
        flash('Git CLI data uploaded', 'success')
    except Exception as e:
        flash(f'Upload failed: {e}', 'danger')
    return redirect(url_for('retrieve'))

@app.route('/upload/git-txt', methods=['POST'])
def upload_git_cli_txt():
    # Accept a plain text output from git CLI and convert to JSON changes
    try:
        repo_id = request.form.get('repo_id') or 'manual'
        if 'file' not in request.files:
            flash('No file uploaded', 'warning')
            return redirect(url_for('retrieve'))
        f = request.files['file']
        parsed = parse_git_txt(f.stream)
        data = {'repo': repo_id, 'changes': parsed.get('changes') or []}
        store_git_cli_upload(repo_id, data)
        # Rebuild correlations summary after new git data arrives
        try:
            ensure_audits_summary_fresh()
            build_and_store_correlations_summary()
        except Exception:
            pass
        flash('Git CLI text uploaded and parsed', 'success')
    except Exception as e:
        flash(f'Upload failed: {e}', 'danger')
    return redirect(url_for('retrieve'))


def _collect_retrieve_page_data(servers, repos):
    bundles = {}
    bundle_labels = {}
    root = os.path.join(DATA_DIR, 'diagnostics_bundles')
    for s in servers:
        sid = s['id']
        bundle_labels[sid] = s.get('name') or sid
        sdir = os.path.join(root, sid)
        files = []
        if os.path.exists(sdir):
            files = sorted(os.listdir(sdir), reverse=True)
        bundles[sid] = files

    gh_reports = {}
    gh_labels = {}
    gh_root = os.path.join(DATA_DIR, 'github_reports')
    cli_root = os.path.join(GIT_CLI_DIR)
    for r in repos:
        rid = r['id']
        gh_labels[rid] = r.get('name') or (r.get('full_name') or rid)
        rdir = os.path.join(gh_root, rid)
        cdir = os.path.join(cli_root, rid)
        files = []
        if os.path.exists(rdir):
            files = sorted([f for f in os.listdir(rdir) if f.endswith('.json')], reverse=True)
        cli_files = []
        if os.path.exists(cdir):
            cli_files = sorted([f for f in os.listdir(cdir) if f.endswith('.json')], reverse=True)
        gh_reports[rid] = {'api': files, 'cli': cli_files}

    return bundles, bundle_labels, gh_reports, gh_labels

def _run_retrieval_job(job_id: str, servers, repos, server_passwords, repo_tokens):
    results = []
    github_results = []
    failures = 0
    github_failures = 0
    total_overall = len(servers) + len(repos)
    completed_ids = []
    _write_progress('lightrun', current='', completed=[], total=total_overall)
    try:
        for s in servers:
            try:
                app.logger.debug('Retrieving for server id=%s name=%s url=%s', s.get('id'), s.get('name'), s.get('url'))
                base = s['url'].rstrip('/')
                email = s.get('email', '')
                pwd = server_passwords.get(s.get('id'), '') or ''
                _write_progress('lightrun', current=(s.get('name') or s.get('id')), completed=completed_ids, total=total_overall)
                auth = lr_authenticate(base, email, pwd, timeout=15, verify=False)
                if not auth.get('ok'):
                    app.logger.warning('Auth failed for server %s: %s', s.get('id'), auth)
                    diag = auth.get('diag') or {}
                    detail_body = diag.get('body')
                    if not isinstance(detail_body, str):
                        detail_body = ''
                    results.append({
                        'server': s.get('id'),
                        'error': f"Auth failed: {diag.get('status')}",
                        'detail': (detail_body or '')[:500],
                        'headers': diag.get('headers') or {}
                    })
                    completed_ids.append(s.get('name') or s.get('id'))
                    _write_progress('lightrun', current='', completed=completed_ids, total=total_overall)
                    continue
                auth_cookie = auth.get('cookie') or {}
                body = lr_diag_body(s.get('name', 'server'))
                ok, st_code, reason = lr_start_diagnostics(base, auth_cookie, body, timeout=20, verify=False)
                if not ok:
                    app.logger.warning('Diagnostics start failed for %s status=%s reason=%s', s.get('id'), st_code, reason)
                    failures += 1
                    results.append({'server': s.get('id'), 'error': "Diagnostics start failed", 'status': st_code, 'reason': reason})
                    completed_ids.append(s.get('name') or s.get('id'))
                    _write_progress('lightrun', current='', completed=completed_ids, total=total_overall)
                    continue
                status_info = lr_poll_status(base, auth_cookie, timeout=20, verify=False, max_iters=120, max_wait_seconds=600)
                app.logger.debug('Diagnostics status for %s: %s', s.get('id'), status_info)
                if status_info.get('status') == 'COMPLETED':
                    dl_status, dl_headers, dl_content = lr_download(base, auth_cookie, timeout=60, verify=False)
                    app.logger.debug('Download status=%s content-type=%s', dl_status, dl_headers.get('Content-Type'))
                    ctype = (dl_headers.get('Content-Type') or '').lower()
                    if dl_status == 200:
                        path = store_diagnostics_zip(s, dl_content)
                        results.append({'server': s.get('id'), 'diagnostics': 'COMPLETED', 'bundle': path, 'content_type': ctype})
                    else:
                        failures += 1
                        results.append({'server': s.get('id'), 'diagnostics': 'COMPLETED', 'error': "Download failed", 'status': dl_status})
                else:
                    failures += 1
                    results.append({'server': s.get('id'), 'diagnostics': 'started', 'status': status_info})
                try:
                    from datetime import timedelta
                    today = datetime.utcnow().date()
                    monday = today - timedelta(days=today.weekday())
                    to_date = monday.strftime('%Y-%m-%d')
                    from_date = (monday - timedelta(weeks=13)).strftime('%Y-%m-%d')
                    audits_payload = fetch_audits_for_server(s, from_date, to_date, auth_cookie, progress_cb=True)
                    if isinstance(audits_payload, dict):
                        store_audits(s, audits_payload)
                        app.logger.info('Stored audits for %s entries=%d', s.get('id'), len(audits_payload.get('entries') or []))
                except Exception as ae:
                    app.logger.exception('Audits fetch failed for %s', s.get('id'))
                    results.append({'server': s.get('id'), 'audits_error': str(ae)})
            except Exception as e:
                results.append({'server': s.get('id'), 'error': str(e)})
                failures += 1
            completed_ids.append(s.get('name') or s.get('id'))
            _write_progress('lightrun', current='', completed=completed_ids, total=total_overall)

        try:
            build_audits_summary()
        except Exception:
            pass

        completed_repos = []
        _write_progress('github', current='', completed=[], total=total_overall)
        from datetime import timedelta
        now = datetime.utcnow()
        since_default = (now - timedelta(days=30)).isoformat(timespec='seconds') + 'Z'
        for r in repos:
            full_name = r.get('full_name') or ''
            try:
                app.logger.debug('GitHub repo retrieval id=%s name=%s full=%s', r.get('id'), r.get('name'), full_name)
                token = repo_tokens.get(r.get('id'), '') or ''
                api_base = (r.get('api_base') or '').strip() or None
                latest_generated_at = gh_latest_generated_at(r.get('id'), DATA_DIR)
                since = latest_generated_at or r.get('last_checked') or since_default
                _write_progress('github', current=(r.get('name') or full_name), completed=completed_repos, total=total_overall)
                commits = gh_list_commits(full_name, token, since_iso=since, until_iso=now.isoformat(timespec='seconds') + 'Z', api_base=api_base)
                app.logger.info('Fetched %d commits for %s since=%s', len(commits), full_name, since)
                repo_changes = []
                for c in commits[:200]:
                    sha = c.get('sha')
                    date = ((c.get('commit') or {}).get('author') or {}).get('date')
                    author_login = (c.get('author') or {}).get('login')
                    author_name = ((c.get('commit') or {}).get('author') or {}).get('name')
                    ok, st, body = gh_commit_details(full_name, sha, token, api_base=api_base)
                    if not ok or not isinstance(body, dict):
                        continue
                    files = [f.get('filename') for f in (body.get('files') or []) if isinstance(f, dict) and f.get('filename')]
                    repo_changes.append({'commit': sha, 'date': date, 'user': author_login or author_name or 'unknown', 'files': files})
                report = {'repo': r.get('name') or full_name, 'full_name': full_name, 'generated_at': now.isoformat(timespec='seconds') + 'Z', 'changes': repo_changes}
                github_results.append(report)
                gh_store_report(r, json.dumps(report), DATA_DIR)
                app.logger.info('Stored GitHub report for %s changes=%d', full_name, len(repo_changes))
                r['last_checked'] = now.isoformat(timespec='seconds') + 'Z'
            except Exception as e:
                app.logger.exception('GitHub retrieval failed for %s', r.get('full_name'))
                github_results.append({'repo': r.get('name') or r.get('full_name'), 'error': str(e)})
                github_failures += 1
            completed_repos.append(r.get('name') or full_name)
            _write_progress('github', current='', completed=completed_repos, total=total_overall)

        set_servers_for('github', repos)
        try:
            ensure_audits_summary_fresh()
            build_and_store_correlations_summary()
        except Exception:
            pass

        _update_job(
            job_id,
            state='completed',
            finished_at=_utc_now_iso(),
            failures=failures,
            github_failures=github_failures,
            had_errors=bool(failures or github_failures),
            results=results,
            github_results=github_results,
            error='',
        )
    except Exception as e:
        app.logger.exception('Retrieval job %s failed with an unexpected error', job_id)
        _update_job(
            job_id,
            state='failed',
            finished_at=_utc_now_iso(),
            failures=failures,
            github_failures=github_failures,
            had_errors=True,
            results=results,
            github_results=github_results,
            error=str(e),
            traceback=traceback.format_exc(),
        )
    finally:
        _clear_progress()
        _release_active_job(job_id)

@app.route('/retrieve/start', methods=['POST'])
def retrieve_start():
    if not session.get('LR_PWD'):
        return jsonify({'ok': False, 'error': 'Master password is not set'}), 400

    servers = get_servers_for('lightrun')
    repos = get_servers_for('github')
    total_overall = len(servers) + len(repos)
    if total_overall == 0:
        return jsonify({'ok': False, 'error': 'No servers or repos configured'}), 400

    server_passwords = {}
    for s in servers:
        sid = s.get('id')
        stored = s.get('password') or ''
        if isinstance(stored, str) and stored.startswith('x:'):
            pwd = decrypt_password(stored)
            if pwd == '':
                return jsonify({'ok': False, 'error': 'Master password is invalid. Please set it again on the home page.'}), 400
        else:
            pwd = stored or ''
        server_passwords[sid] = pwd

    repo_tokens = {}
    for r in repos:
        rid = r.get('id')
        token_stored = r.get('token') or ''
        token = decrypt_password(token_stored) if token_stored else ''
        repo_tokens[rid] = token

    job_id = uuid.uuid4().hex
    acquired, active_job_id = _acquire_active_job(job_id)
    if not acquired:
        return jsonify({'ok': False, 'error': 'A retrieval job is already running', 'job_id': active_job_id}), 409

    _clear_progress()
    _write_progress('lightrun', current='', completed=[], total=total_overall)
    _write_progress('github', current='', completed=[], total=total_overall)
    _write_job(job_id, {
        'job_id': job_id,
        'state': 'running',
        'created_at': _utc_now_iso(),
        'started_at': _utc_now_iso(),
        'finished_at': '',
        'total_overall': total_overall,
        'failures': 0,
        'github_failures': 0,
        'had_errors': False,
        'results': [],
        'github_results': [],
        'error': '',
    })

    t = threading.Thread(
        target=_run_retrieval_job,
        args=(job_id, servers, repos, server_passwords, repo_tokens),
        daemon=True,
        name=f"retrieve-{job_id[:8]}",
    )
    t.start()
    return jsonify({'ok': True, 'job_id': job_id, 'status_url': url_for('retrieve_status', job_id=job_id)}), 202

@app.route('/retrieve/status/<job_id>')
def retrieve_status(job_id):
    job = _read_job(job_id)
    if not job:
        return jsonify({'ok': False, 'error': 'job not found'}), 404
    snap = _progress_snapshot()
    active_job_id = _read_active_job_id()
    return jsonify({
        'ok': True,
        'job_id': job_id,
        'state': job.get('state'),
        'created_at': job.get('created_at'),
        'started_at': job.get('started_at'),
        'finished_at': job.get('finished_at'),
        'had_errors': bool(job.get('had_errors')),
        'failures': int(job.get('failures') or 0),
        'github_failures': int(job.get('github_failures') or 0),
        'error': job.get('error') or '',
        'progress': snap,
        'active': active_job_id == job_id,
    }), 200

@app.route('/retrieve', methods=['GET'])
def retrieve():
    servers = get_servers_for('lightrun')
    repos = get_servers_for('github')
    app.logger.info('Retrieve %s: servers=%d repos=%d method=%s', request.path, len(servers), len(repos), request.method)

    results = []
    github_results = []
    job_id = (request.args.get('job_id') or '').strip()
    notify = (request.args.get('notify') or '').strip() == '1'
    if job_id:
        job = _read_job(job_id)
        if job:
            results = job.get('results') or []
            github_results = job.get('github_results') or []
            if notify:
                if job.get('state') == 'completed' and not job.get('had_errors'):
                    flash('Retrieval finished', 'success')
                elif job.get('state') == 'completed':
                    flash('Communication with some servers failed. Check the Debug details below.', 'danger')
                elif job.get('state') == 'failed':
                    flash(f"Retrieval failed: {job.get('error') or 'unknown error'}", 'danger')
        elif notify:
            flash('Retrieval job was not found', 'warning')

    bundles, bundle_labels, gh_reports, gh_labels = _collect_retrieve_page_data(servers, repos)
    total_overall = len(servers) + len(repos)
    active_job_id = _read_active_job_id()

    try:
        ensure_usage_summary_fresh()
    except Exception:
        pass
    try:
        ensure_audits_summary_fresh()
    except Exception:
        pass
    return render_template(
        'retrieval.html',
        servers=servers,
        results=results,
        bundles=bundles,
        bundle_labels=bundle_labels,
        github_results=github_results,
        gh_reports=gh_reports,
        gh_labels=gh_labels,
        total_overall=total_overall,
        active_job_id=active_job_id,
        master_password_warning=_master_password_warning(),
    )


@app.route('/display')
def display():
    ensure_usage_summary_fresh()
    ensure_audits_summary_fresh()
    summary = {}
    try:
        with open(USAGE_SUMMARY_PATH, 'r') as f:
            summary = json.load(f)
    except Exception:
        summary = {'daily': {}, 'weeks': {}}
    # Prepare last 13 weeks timeline
    from datetime import datetime, timedelta
    # Apply server filter to weeks before building the timeline
    server_id = request.args.get('server')
    weeks = summary.get('weeks') or {}
    if server_id and server_id != 'all':
        weeks = (summary.get('weeks_by_server') or {}).get(server_id) or {}
    week_keys = sorted(weeks.keys())
    # Build timeline primarily from audits totals to match week details; fallback to usage when audits missing
    audits_summary = {}
    try:
        with open(os.path.join(SUMMARIES_DIR, 'audits_summary.json'), 'r') as f:
            audits_summary = json.load(f)
    except Exception:
        audits_summary = {'weeks': {}}
    audits_weeks = (audits_summary.get('weeks') or {})
    if server_id and server_id != 'all':
        audits_weeks = (audits_summary.get('weeks_by_server') or {}).get(server_id) or {}
    constructed = []
    today = datetime.utcnow()
    anchor = today - timedelta(days=today.weekday())
    anchors = [(anchor - timedelta(weeks=i)).strftime('%Y-%m-%d') for i in range(13)]
    any_data = False
    for k in anchors:
        a_total = (audits_weeks.get(k) or {}).get('total', 0)
        total = a_total
        if total:
            any_data = True
        constructed.append({'week': k, 'total': total})
    if not any_data:
        # fallback to usage totals if audits provide no data
        constructed = []
        for k in anchors:
            u_total = (weeks.get(k) or {}).get('total', 0)
            constructed.append({'week': k, 'total': u_total})
        if not any(w.get('total', 0) for w in constructed):
            # fallback to last available usage weeks
            constructed = []
            for k in week_keys[-13:]:
                constructed.append({'week': k, 'total': (weeks.get(k) or {}).get('total', 0)})
    last_weeks = constructed
    # server_id already applied to weeks above
    # Top users over last 13 weeks (use audits summary attribution)
    # Use audits weeks (filtered as above) for top users aggregation
    user_counts = {}
    for item in last_weeks:
        wk = item['week']
        wentry = audits_weeks.get(wk) or {}
        for u, cnt in (wentry.get('usersCounts') or {}).items():
            user_counts[u] = user_counts.get(u, 0) + cnt
    top_users = sorted(([{'user': u, 'total': c} for u, c in user_counts.items() if c > 0]), key=lambda x: x['total'], reverse=True)
    # Build correlations from persisted summary, so exported bundles can
    # reproduce Display without raw git/audits data.
    corr_weeks = audits_weeks if (server_id and server_id != 'all') else (audits_summary.get('weeks') or {})
    correlations = load_correlations_summary(
        selected_server=(server_id if (server_id and server_id != 'all') else None),
        week_whitelist=(corr_weeks.keys() if isinstance(corr_weeks, dict) else []),
    )
    if not correlations:
        # Backward-compatible fallback for environments that don't yet have
        # summaries/correlations.json.
        correlations = build_correlations(corr_weeks)
    total_corr = len(correlations)
    # Logging for troubleshooting timeline data
    try:
        app.logger.info('Display timeline weeks count=%d', len(last_weeks))
        app.logger.info('Display weeks keys present=%s', ','.join(sorted(list(weeks.keys()))[-13:]))
        app.logger.info('Display timeline sample=%s', last_weeks[:5])
        app.logger.info('Display top_users sample=%s', top_users[:5])
    except Exception:
        pass
    # Build server id->name mapping for selector
    lr_servers = get_servers_for('lightrun')
    server_labels = {s.get('id'): (s.get('name') or s.get('id')) for s in lr_servers}
    return render_template('display.html', timeline=last_weeks, top_users=top_users, correlations=correlations, total_corr=total_corr, servers=server_labels, selected_server=server_id or 'all')

@app.route('/display/week/<week_start>')
def display_week(week_start):
    # Use audits summary for detailed per-week users and actions
    try:
        with open(os.path.join(SUMMARIES_DIR, 'audits_summary.json'), 'r') as f:
            audits_summary = json.load(f)
    except Exception:
        return jsonify({'error': 'summary not available'}), 404
    server_id = request.args.get('server')
    audits_weeks = audits_summary.get('weeks') or {}
    if server_id:
        audits_weeks = (audits_summary.get('weeks_by_server') or {}).get(server_id) or {}
    w = audits_weeks.get(week_start)
    if not w:
        return jsonify({'week': week_start, 'users': [], 'actions': {}})
    users_sorted = sorted(([{'user': u, 'total': t} for u, t in (w.get('usersCounts') or {}).items() if t > 0]), key=lambda x: x['total'], reverse=True)
    return jsonify({'week': week_start, 'users': users_sorted, 'actions': w.get('actionCounts') or {}})


@app.route('/export')
def export():
    # Export diagnostics_bundles and summaries only
    return export_bundles()


@app.route('/data/<server_id>/<path:filename>')
def serve_data(server_id, filename):
    # Serve stored data file from DATA_DIR safely
    sdir = os.path.join(DATA_DIR, server_id)
    target = os.path.join(sdir, filename)
    if not os.path.exists(target):
        return ("Not found", 404)
    return send_file(target, as_attachment=False)


@app.route('/bundles/<server_id>/<path:filename>')
def serve_bundle(server_id, filename):
    # Serve diagnostics bundle zip from DATA_DIR/diagnostics_bundles/<server_id>
    bdir = os.path.join(DATA_DIR, 'diagnostics_bundles', server_id)
    target = os.path.join(bdir, filename)
    if not os.path.exists(target):
        return ("Not found", 404)
    return send_file(target, as_attachment=True, download_name=filename)

@app.route('/gh_reports/<repo_id>/<path:filename>')
def serve_gh_report(repo_id, filename):
    # Serve stored GitHub report JSON from DATA_DIR/github_reports/<repo_id>
    rdir = os.path.join(DATA_DIR, 'github_reports', repo_id)
    target = os.path.join(rdir, filename)
    if not os.path.exists(target):
        return ("Not found", 404)
    return send_file(target, as_attachment=True, download_name=filename)

@app.route('/cli_reports/<repo_id>/<path:filename>')
def serve_cli_report(repo_id, filename):
    # Serve stored CLI-uploaded git JSON from DATA_DIR/git_cli/<repo_id>
    rdir = os.path.join(GIT_CLI_DIR, repo_id)
    target = os.path.join(rdir, filename)
    if not os.path.exists(target):
        return ("Not found", 404)
    return send_file(target, as_attachment=True, download_name=filename)


@app.route('/export/bundles')
def export_bundles():
    # Create a zip containing diagnostics bundles and non-sensitive summaries.
    # Summaries include precomputed correlations for Display reproducibility.
    try:
        ensure_usage_summary_fresh()
    except Exception:
        pass
    try:
        ensure_audits_summary_fresh()
    except Exception:
        pass
    try:
        build_and_store_correlations_summary()
    except Exception:
        pass

    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        export_roots = [
            os.path.join(DATA_DIR, 'diagnostics_bundles'),
            SUMMARIES_DIR,
        ]
        for root in export_roots:
            if not os.path.exists(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                for fn in filenames:
                    fp = os.path.join(dirpath, fn)
                    rel = os.path.relpath(fp, DATA_DIR)
                    z.write(fp, arcname=rel)
    mem.seek(0)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    return send_file(mem, as_attachment=True, download_name=f"lrmetrics_data_{ts}.zip")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
