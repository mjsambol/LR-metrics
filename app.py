import os
import json
import hashlib
import zipfile
import io
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
)
import requests
from requests.auth import HTTPBasicAuth
from base64 import urlsafe_b64encode, urlsafe_b64decode
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret')

DATA_DIR = os.environ.get('DATA_DIR', '/data')
os.makedirs(DATA_DIR, exist_ok=True)
CONFIG_PATH = os.path.join(DATA_DIR, 'servers.json')
PROGRESS_PATH = os.path.join(DATA_DIR, 'progress.json')
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
        flash('Please set the master password before using the app.', 'danger')
        return redirect(url_for('index'))


from flask import session
# Master password is now provided by user via landing page and stored in session
# Simple password-based protection helpers
def _key_bytes():
    pwd = session.get('LR_PWD') or ''
    return hashlib.sha256(pwd.encode()).digest()

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


def load_config():
    # config is a dict of source_type -> list of servers
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, 'r') as f:
        try:
            c = json.load(f)
        except Exception:
            return {}
    # do not perform format migrations; expect dict format
    return c


def save_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)


def get_servers_for(src_type):
    config = load_config()
    return config.get(src_type, [])


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
                        # overall daily
                        entry = daily.get(dstr) or {'total': 0, 'users': set(), 'actionCounts': {}}
                        entry['total'] += total
                        entry['users'].update(users)
                        if isinstance(actions, dict):
                            ac = entry['actionCounts']
                            for k, v in actions.items():
                                try:
                                    ac[k] = ac.get(k, 0) + int(v)
                                except Exception:
                                    pass
                        daily[dstr] = entry
                        # per-server daily
                        sentry = daily_by_server[sid].get(dstr) or {'total': 0, 'users': set(), 'actionCounts': {}}
                        sentry['total'] += total
                        sentry['users'].update(users)
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
    for sid, dmap in daily_by_server.items():
        for dstr, entry in dmap.items():
            entry['users'] = sorted(list(entry['users']))
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
                _write_progress('lightrun', current=f"{server.get('name') or server.get('id')} · page {page}", completed=[], total=PAGE_SIZE)
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
    # Validate password by attempting to decrypt one stored password if present
    if has_pwd:
        cfg = load_config()
        for servers in cfg.values():
            for s in servers:
                sp = s.get('password')
                if isinstance(sp, str) and sp.startswith('x:'):
                    val = decrypt_password(sp)
                    if val == '':
                        has_pwd = False
                    break
    return render_template('index.html', last_retrieved=last, has_pwd=has_pwd)


@app.route('/set-password', methods=['POST'])
def set_password():
    pwd = request.form.get('master_password', '').strip()
    if not pwd:
        flash('Please enter a password', 'danger')
        return redirect(url_for('index'))
    session['LR_PWD'] = pwd
    flash('Password set', 'success')
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('LR_PWD', None)
    flash('Password cleared. Set it again to continue.', 'info')
    return redirect(url_for('index'))


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    src = request.args.get('src', 'lightrun')
    servers = get_servers_for(src)
    if request.method == 'POST':
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
    return render_template('setup.html', src=src, servers=servers)


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
    return render_template('setup_edit.html', src=src, server=s)


@app.route('/setup/delete/<src>/<server_id>', methods=['POST'])
def setup_delete(src, server_id):
    servers = get_servers_for(src)
    new = [x for x in servers if x.get('id') != server_id]
    set_servers_for(src, new)
    flash('Server removed', 'info')
    return redirect(url_for('setup', src=src))


@app.route('/retrieve', methods=['GET', 'POST'])
def retrieve():
    servers = get_servers_for('lightrun')
    repos = get_servers_for('github')
    results = []
    github_results = []
    if request.method == 'POST':
        if not session.get('LR_PWD'):
            flash('Set the master password on the home page before retrieval.', 'danger')
            return redirect(url_for('retrieve'))
        failures = 0
        github_failures = 0
        total_overall = len(servers) + len(repos)
        completed_ids = []
        _write_progress('lightrun', current='', completed=[], total=total_overall)
        for s in servers:
            try:
                base = s['url'].rstrip('/')
                email = s.get('email', '')
                stored = s.get('password') or ''
                if isinstance(stored, str) and stored.startswith('x:'):
                    pwd = decrypt_password(stored)
                    if pwd == '':
                        flash('Master password is invalid. Please set it again on the home page.', 'danger')
                        return redirect(url_for('index'))
                else:
                    pwd = stored or ''
                # mark current
                _write_progress('lightrun', current=(s.get('name') or s.get('id')), completed=completed_ids, total=len(servers))
                # authenticate to get cookie
                auth = lr_authenticate(base, email, pwd, timeout=15, verify=False)
                if not auth.get('ok'):
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
                # prepare diagnostics via API helper
                body = lr_diag_body(s.get('name','server'))
                ok, st_code, reason = lr_start_diagnostics(base, auth_cookie, body, timeout=20, verify=False)
                if not ok:
                    failures += 1
                    results.append({'server': s.get('id'), 'error': "Diagnostics start failed", 'status': st_code, 'reason': reason})
                    completed_ids.append(s.get('name') or s.get('id'))
                    _write_progress('lightrun', current='', completed=completed_ids, total=total_overall)
                    continue
                # poll status until COMPLETED
                status_info = lr_poll_status(base, auth_cookie, timeout=20, verify=False, max_iters=120)
                # if completed, download the bundle
                if status_info.get('status') == 'COMPLETED':
                    dl_status, dl_headers, dl_content = lr_download(base, auth_cookie, timeout=60, verify=False)
                    ctype = (dl_headers.get('Content-Type') or '').lower()
                    if dl_status == 200:
                        # Save regardless of content-type; browsers download zip immediately even without correct header
                        path = store_diagnostics_zip(s, dl_content)
                        results.append({'server': s.get('id'), 'diagnostics': 'COMPLETED', 'bundle': path, 'content_type': ctype})
                    else:
                        failures += 1
                        results.append({'server': s.get('id'), 'diagnostics': 'COMPLETED', 'error': "Download failed", 'status': dl_status})
                else:
                    # status failure or timeout
                    failures += 1
                    results.append({'server': s.get('id'), 'diagnostics': 'started', 'status': status_info})
                # Fetch audits for the last 13 weeks window
                try:
                    from datetime import timedelta
                    # Anchor window to current Monday (start of week)
                    today = datetime.utcnow().date()
                    monday = today - timedelta(days=today.weekday())
                    to_date = monday.strftime('%Y-%m-%d')
                    from_date = (monday - timedelta(weeks=13)).strftime('%Y-%m-%d')
                    # Progress will show "Server · page N" as pages advance
                    audits_payload = fetch_audits_for_server(s, from_date, to_date, auth_cookie, progress_cb=True)
                    if isinstance(audits_payload, dict):
                        store_audits(s, audits_payload)
                except Exception as ae:
                    results.append({'server': s.get('id'), 'audits_error': str(ae)})
            except Exception as e:
                results.append({'server': s.get('id'), 'error': str(e)})
                failures += 1
            # mark completion of this server
            completed_ids.append(s.get('name') or s.get('id'))
            _write_progress('lightrun', current='', completed=completed_ids, total=total_overall)
        # After audits fetched for all servers, rebuild audits summary
        try:
            build_audits_summary()
        except Exception:
            pass
        # Process GitHub repos as part of unified retrieval
        completed_repos = []
        _write_progress('github', current='', completed=[], total=total_overall)
        from datetime import timedelta
        now = datetime.utcnow()
        since_default = (now - timedelta(days=30)).isoformat(timespec='seconds') + 'Z'
        for r in repos:
            try:
                token_stored = r.get('token') or ''
                token = decrypt_password(token_stored) if token_stored else ''
                full_name = r.get('full_name') or ''
                api_base = (r.get('api_base') or '').strip() or None
                # Determine since based on latest stored report timestamp if present; otherwise 30-day default
                latest_generated_at = gh_latest_generated_at(r.get('id'), DATA_DIR)
                since = latest_generated_at or r.get('last_checked') or since_default
                _write_progress('github', current=(r.get('name') or full_name), completed=completed_repos, total=total_overall)
                commits = gh_list_commits(full_name, token, since_iso=since, until_iso=now.isoformat(timespec='seconds') + 'Z', api_base=api_base)
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
                # assemble report and store to filesystem
                report = {'repo': r.get('name') or full_name, 'full_name': full_name, 'generated_at': now.isoformat(timespec='seconds') + 'Z', 'changes': repo_changes}
                github_results.append(report)
                gh_store_report(r, json.dumps(report), DATA_DIR)
                r['last_checked'] = now.isoformat(timespec='seconds') + 'Z'
            except Exception as e:
                github_results.append({'repo': r.get('name') or r.get('full_name'), 'error': str(e)})
                github_failures += 1
            completed_repos.append(r.get('name') or full_name)
            _write_progress('github', current='', completed=completed_repos, total=total_overall)
        set_servers_for('github', repos)

        if failures or github_failures:
            flash('Communication with some servers failed. Check the Debug details below.', 'danger')
        else:
            flash('Retrieval finished', 'success')
        _clear_progress()
        try:
            print("[LRmetrics] Retrieval results:")
            for r in results:
                try:
                    print(json.dumps(r, indent=2))
                except Exception:
                    print(str(r))
            print("[LRmetrics] GitHub Retrieval results:")
            for r in github_results:
                try:
                    print(json.dumps(r, indent=2))
                except Exception:
                    print(str(r))
        except Exception:
            pass
    # list latest diagnostics bundles for display
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

    # list latest github reports for display
    gh_reports = {}
    gh_labels = {}
    gh_root = os.path.join(DATA_DIR, 'github_reports')
    for r in repos:
        rid = r['id']
        gh_labels[rid] = r.get('name') or (r.get('full_name') or rid)
        rdir = os.path.join(gh_root, rid)
        files = []
        if os.path.exists(rdir):
            files = sorted([f for f in os.listdir(rdir) if f.endswith('.json')], reverse=True)
        gh_reports[rid] = files

    total_overall = len(servers) + len(repos)
    return render_template('retrieval.html', servers=servers, results=results, bundles=bundles, bundle_labels=bundle_labels, github_results=github_results, gh_reports=gh_reports, gh_labels=gh_labels, total_overall=total_overall)


@app.route('/display')
def display():
    ensure_usage_summary_fresh()
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
    return render_template('display.html', timeline=last_weeks, top_users=top_users, servers=server_labels, selected_server=server_id or 'all')

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
    # Rewired to export latest diagnostics bundles zip-of-zips
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


@app.route('/export/bundles')
def export_bundles():
    # Create a zip containing latest bundle for each server and latest GitHub reports
    servers = get_servers_for('lightrun')
    repos = get_servers_for('github')
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        # Lightrun bundles
        root = os.path.join(DATA_DIR, 'diagnostics_bundles')
        for s in servers:
            sid = s.get('id')
            sname = (s.get('name') or sid).strip()
            sdir = os.path.join(root, sid)
            if not os.path.exists(sdir):
                continue
            files = [f for f in os.listdir(sdir) if f.endswith('.zip')]
            if not files:
                continue
            latest = sorted(files, reverse=True)[0]
            z.write(os.path.join(sdir, latest), arcname=f"lightrun/{sname}/{latest}")
        # GitHub reports
        gh_root = os.path.join(DATA_DIR, 'github_reports')
        for r in repos:
            rid = r.get('id')
            rname = (r.get('name') or (r.get('full_name') or rid)).strip()
            rdir = os.path.join(gh_root, rid)
            if not os.path.exists(rdir):
                continue
            files = [f for f in os.listdir(rdir) if f.endswith('.json')]
            if not files:
                continue
            latest = sorted(files, reverse=True)[0]
            z.write(os.path.join(rdir, latest), arcname=f"github/{rname}/{latest}")
    mem.seek(0)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    return send_file(mem, as_attachment=True, download_name=f"lrmetrics_bundles_{ts}.zip")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
