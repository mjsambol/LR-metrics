import os
import sys
import json
import uuid
import hashlib
import zipfile
import io
import re
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


# removed duplicate encryption helpers (defined earlier)

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


# No migration logic: existing data is used as-is


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


def test_connection(server):
    try:
        # GET the /version endpoint
        base = server.get('url', '').rstrip('/')
        url = f"{base}/version"
        # Tolerate self-signed certificates
        resp = requests.get(url, timeout=10, verify=False)
        text = resp.text.strip()
        if resp.status_code == 200:
            # remove leading 'Lightrun Server' if present
            ver = re.sub(r'(?i)^\s*Lightrun Server\s*', '', text).strip()
            # attempt authentication
            auth_result = {'ok': False}
            try:
                auth_url = f"{base}/api/authenticate"
                auth_payload = {"email": server.get('email', ''), "password": server.get('password', ''), "rememberMe": True}
                auth_resp = requests.post(auth_url, json=auth_payload, timeout=10, verify=False)
                # Collect diagnostics
                diag = {
                    'status': auth_resp.status_code,
                    'url': auth_url,
                    'payload': {k: (v if k != 'password' else '***') for k, v in auth_payload.items()},
                    'headers': dict(auth_resp.headers),
                }
                text_snippet = ''
                body_json = None
                try:
                    body_json = auth_resp.json()
                except Exception as je:
                    diag['json_error'] = str(je)
                    text_snippet = (auth_resp.text or '')[:500]
                if body_json is None:
                    diag['body'] = text_snippet
                else:
                    diag['body'] = body_json

                if auth_resp.status_code == 200 and isinstance(body_json, dict) and 'id_token' in body_json:
                    cookie_val = {'access_token': body_json.get('id_token')}
                    auth_result = {'ok': True, 'cookie': cookie_val, 'diag': diag}
                else:
                    auth_result = {'ok': False, 'error': 'Authentication failed', 'diag': diag}
            except Exception as e:
                auth_result = {'ok': False, 'error': str(e)}
            return True, resp.status_code, {'version': ver, 'auth': auth_result}
        return False, resp.status_code, text[:400]
    except Exception as e:
        return False, None, str(e)


# (Removed corrupted duplicate encryption helper block)



# No encryption validation or migrations


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
            flash('Set the master password on the home page before saving servers.', 'danger')
            return redirect(url_for('setup', src=src))
        # creation of a new server for the selected source
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
        # Server-side authentication test required before saving
        server_for_test = {'id': sid, 'name': name, 'url': url.rstrip('/'), 'email': email, 'password': password}
        ok, status, info = test_connection(server_for_test)
        if not ok:
            flash(f'Connection test failed: {info}', 'danger')
            return redirect(url_for('setup', src=src))
        # require successful authentication
        if isinstance(info, dict):
            auth = info.get('auth') or {}
            if not auth.get('ok'):
                diag = auth.get('diag') or {}
                detail = f"status={diag.get('status')} url={diag.get('url')}"
                body = diag.get('body')
                if isinstance(body, str):
                    detail += f" body_snippet={body[:120]}"
                elif isinstance(body, dict):
                    # show keys for quick hint
                    detail += f" body_keys={list(body.keys())}"
                flash(f'Authentication failed — server not saved ({detail})', 'danger')
                return redirect(url_for('setup', src=src))
        # store password encrypted with LRMETRICS_PWD
        server['password'] = encrypt_password(password)
        servers.append(server)
        set_servers_for(src, servers)
        # store version if available (do not persist auth_ok flags)
        if isinstance(info, dict):
            ver = info.get('version')
            if ver:
                server['version'] = ver
        set_servers_for(src, servers)
        flash('Server saved', 'success')
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
    results = []
    if request.method == 'POST':
        if not session.get('LR_PWD'):
            flash('Set the master password on the home page before retrieval.', 'danger')
            return redirect(url_for('retrieve'))
        failures = 0
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
                # authenticate to get cookie
                auth_resp = requests.post(f"{base}/api/authenticate", json={"email": email, "password": pwd, "rememberMe": True}, timeout=15, verify=False)
                if auth_resp.status_code != 200:
                    results.append({
                        'server': s.get('id'),
                        'error': f"Auth failed: {auth_resp.status_code}",
                        'detail': (auth_resp.text or '')[:500],
                        'headers': dict(auth_resp.headers)
                    })
                    continue
                auth_cookie = None
                if "id_token" not in auth_resp.json():
                    results.append({
                        'server': s.get('id'),
                        'error': "Auth cookie not found after authentication",
                        'body_keys': list((auth_resp.json() or {}).keys()) if isinstance(auth_resp.json(), dict) else 'non-json'
                    })
                    continue
                auth_cookie = {"access_token": auth_resp.json().get("id_token")}
                # prepare diagnostics
                body = {
                    "diagnostics": [
                        "KEYCLOAK","ENVIRONMENT_VARIABLES","FEATURE_TOGGLES","DB_TABLES_INFO","K8S_INFO",
                        "INTEGRATIONS","LICENSES_INFO","USAGE_INFO","AGENTS","PLUGINS","ACTIONS_INFO",
                        "COMPANY_SETTINGS","REPORT_CONFIG"
                    ],
                    "logCollectionSettings": {"useRandomClients": True},
                    "shouldAnonymize": False,
                    "reportDescription": f"{s.get('name','server')} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
                }
                diag_resp = requests.post(f"{base}/athena/diagnostics", json=body, cookies=auth_cookie or {}, timeout=20, verify=False)
                if diag_resp.status_code != 200:
                    failures += 1
                    snippet = ''
                    try:
                        snippet = diag_resp.text[:300]
                    except Exception:
                        snippet = ''
                    results.append({'server': s.get('id'), 'error': "Diagnostics start failed", 'status': diag_resp.status_code, 'reason': snippet})
                    continue
                # poll status until COMPLETED
                status_info = None
                for _ in range(120):  # up to ~2 minutes
                    st_resp = requests.get(f"{base}/athena/diagnostics/status", cookies=auth_cookie or {}, timeout=20, verify=False)
                    if st_resp.status_code != 200:
                        status_info = {'error': "Status failed", 'status': st_resp.status_code}
                        break
                    try:
                        sj = st_resp.json()
                    except Exception:
                        status_info = {'error': 'Invalid status payload'}
                        break
                    if (sj.get('status') or '').upper() == 'COMPLETED':
                        status_info = {'status': 'COMPLETED'}
                        break
                    cooldown = int(sj.get('cooldownMs') or 1000)
                    # sleep ~1s regardless; do not block server excessively
                    import time
                    time.sleep(min(max(cooldown/1000.0, 0.5), 2.0))
                if not status_info:
                    status_info = {'status': 'TIMEOUT'}
                # if completed, download the bundle
                if status_info.get('status') == 'COMPLETED':
                    dl_resp = requests.get(f"{base}/athena/diagnostics/download", cookies=auth_cookie or {}, timeout=60, verify=False)
                    ctype = (dl_resp.headers.get('Content-Type') or '').lower()
                    if dl_resp.status_code == 200:
                        # Save regardless of content-type; browsers download zip immediately even without correct header
                        path = store_diagnostics_zip(s, dl_resp.content)
                        results.append({'server': s.get('id'), 'diagnostics': 'COMPLETED', 'bundle': path, 'content_type': ctype})
                    else:
                        failures += 1
                        results.append({'server': s.get('id'), 'diagnostics': 'COMPLETED', 'error': "Download failed", 'status': dl_resp.status_code})
                else:
                    # status failure or timeout
                    failures += 1
                    results.append({'server': s.get('id'), 'diagnostics': 'started', 'status': status_info})
            except Exception as e:
                results.append({'server': s.get('id'), 'error': str(e)})
                failures += 1
        if failures:
            flash('Some servers failed during retrieval. Please check the master password and try again.', 'danger')
        else:
            flash('Retrieval finished', 'success')
        try:
            print("[LRmetrics] Retrieval results:")
            for r in results:
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
    return render_template('retrieval.html', servers=servers, results=results, bundles=bundles, bundle_labels=bundle_labels)


@app.route('/display')
def display():
    servers = get_servers_for('lightrun')
    summaries = []
    for s in servers:
        sid = s['id']
        sdir = os.path.join(DATA_DIR, sid)
        latest = None
        if os.path.exists(sdir):
            files = sorted(os.listdir(sdir), reverse=True)
            if files:
                latest = files[0]
                with open(os.path.join(sdir, latest), 'r') as f:
                    content = f.read()
                # try to parse JSON to get simple counts
                summary = {'server': sid, 'latest': latest, 'size': os.path.getsize(os.path.join(sdir, latest))}
                try:
                    j = json.loads(content)
                    if isinstance(j, dict):
                        summary['top_keys'] = list(j.keys())[:6]
                    elif isinstance(j, list):
                        summary['items'] = len(j)
                except Exception:
                    summary['preview'] = content[:400]
            else:
                summary = {'server': sid, 'latest': None}
        else:
            summary = {'server': sid, 'latest': None}
        summaries.append(summary)
    return render_template('display.html', summaries=summaries)


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


@app.route('/export/bundles')
def export_bundles():
    # Create a zip containing latest bundle for each server
    servers = get_servers_for('lightrun')
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
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
            z.write(os.path.join(sdir, latest), arcname=f"{sname}/{latest}")
    mem.seek(0)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    return send_file(mem, as_attachment=True, download_name=f"lrmetrics_bundles_{ts}.zip")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
