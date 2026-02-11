import atexit
import io
import json
import os
import shutil
import tempfile
import zipfile
from datetime import datetime, timedelta

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for


app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret')

_STATE = {
    'bundle_dir': '',
}


def _cleanup_bundle_dir():
    path = _STATE.get('bundle_dir') or ''
    if path and os.path.exists(path):
        shutil.rmtree(path, ignore_errors=True)
    _STATE['bundle_dir'] = ''


atexit.register(_cleanup_bundle_dir)


def _safe_extract_zip(file_bytes: bytes, target_dir: str):
    with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
        for member in zf.infolist():
            name = member.filename
            if not name or name.endswith('/'):
                continue
            dest = os.path.abspath(os.path.join(target_dir, name))
            if not dest.startswith(os.path.abspath(target_dir) + os.sep):
                raise ValueError(f"Unsafe zip entry path: {name}")
        zf.extractall(target_dir)


def _bundle_dir() -> str:
    return _STATE.get('bundle_dir') or ''


def _summary_path(filename: str) -> str:
    return os.path.join(_bundle_dir(), 'summaries', filename)


def _load_json(path: str, default):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return default


def _load_usage_summary():
    return _load_json(_summary_path('usage_summary.json'), {'daily': {}, 'weeks': {}, 'weeks_by_server': {}})


def _load_audits_summary():
    return _load_json(_summary_path('audits_summary.json'), {'weeks': {}, 'weeks_by_server': {}})


def _load_correlations_summary():
    return _load_json(_summary_path('correlations.json'), {'weeks': {}, 'total': 0})


def _collect_server_labels():
    root = os.path.join(_bundle_dir(), 'diagnostics_bundles')
    labels = {}
    if not os.path.exists(root):
        return labels
    for sid in sorted(os.listdir(root)):
        sdir = os.path.join(root, sid)
        if os.path.isdir(sdir):
            labels[sid] = sid
    return labels


def _correlations_for_display(selected_server: str, week_whitelist):
    corr_summary = _load_correlations_summary()
    weeks_map = corr_summary.get('weeks') or {}
    week_set = set(week_whitelist or [])
    out = []
    for wk, arr in weeks_map.items():
        if week_set and wk not in week_set:
            continue
        for c in (arr or []):
            if selected_server and selected_server != 'all' and c.get('server') != selected_server:
                continue
            out.append(c)
    out.sort(key=lambda x: x.get('date', ''), reverse=True)
    return out


@app.route('/')
def index():
    loaded = bool(_bundle_dir())
    return render_template('viewer_upload.html', loaded=loaded)


@app.route('/load', methods=['POST'])
def load_bundle():
    if 'bundle' not in request.files:
        flash('Please choose an export zip file.', 'danger')
        return redirect(url_for('index'))
    f = request.files['bundle']
    if not f or not f.filename:
        flash('Please choose an export zip file.', 'danger')
        return redirect(url_for('index'))
    try:
        data = f.read()
        tmp = tempfile.mkdtemp(prefix='lrmetrics-viewer-')
        _safe_extract_zip(data, tmp)
        _cleanup_bundle_dir()
        _STATE['bundle_dir'] = tmp
        if not os.path.exists(_summary_path('usage_summary.json')):
            flash('Bundle is missing summaries/usage_summary.json', 'danger')
            _cleanup_bundle_dir()
            return redirect(url_for('index'))
        flash('Bundle loaded successfully.', 'success')
        return redirect(url_for('display'))
    except Exception as e:
        flash(f'Failed to load bundle: {e}', 'danger')
        _cleanup_bundle_dir()
        return redirect(url_for('index'))


@app.route('/display')
def display():
    if not _bundle_dir():
        flash('Load an export bundle first.', 'warning')
        return redirect(url_for('index'))

    usage = _load_usage_summary()
    audits_summary = _load_audits_summary()
    server_id = request.args.get('server') or 'all'

    weeks = usage.get('weeks') or {}
    if server_id != 'all':
        weeks = (usage.get('weeks_by_server') or {}).get(server_id) or {}
    week_keys = sorted(weeks.keys())

    audits_weeks = audits_summary.get('weeks') or {}
    if server_id != 'all':
        audits_weeks = (audits_summary.get('weeks_by_server') or {}).get(server_id) or {}

    constructed = []
    anchor = datetime.utcnow() - timedelta(days=datetime.utcnow().weekday())
    anchors = [(anchor - timedelta(weeks=i)).strftime('%Y-%m-%d') for i in range(13)]
    any_data = False
    for wk in anchors:
        total = (audits_weeks.get(wk) or {}).get('total', 0)
        if total:
            any_data = True
        constructed.append({'week': wk, 'total': total})
    if not any_data:
        constructed = [{'week': wk, 'total': (weeks.get(wk) or {}).get('total', 0)} for wk in anchors]
        if not any(item.get('total', 0) for item in constructed):
            constructed = [{'week': wk, 'total': (weeks.get(wk) or {}).get('total', 0)} for wk in week_keys[-13:]]
    timeline = constructed

    user_counts = {}
    for item in timeline:
        wk = item['week']
        wentry = audits_weeks.get(wk) or {}
        for user, cnt in (wentry.get('usersCounts') or {}).items():
            user_counts[user] = user_counts.get(user, 0) + cnt
    top_users = sorted(
        [{'user': u, 'total': c} for u, c in user_counts.items() if c > 0],
        key=lambda x: x['total'],
        reverse=True,
    )

    week_whitelist = list(audits_weeks.keys())
    correlations = _correlations_for_display(server_id, week_whitelist)
    servers = _collect_server_labels()

    return render_template(
        'viewer_display.html',
        timeline=timeline,
        top_users=top_users,
        correlations=correlations,
        total_corr=len(correlations),
        servers=servers,
        selected_server=server_id,
    )


@app.route('/display/week/<week_start>')
def display_week(week_start):
    if not _bundle_dir():
        return jsonify({'error': 'bundle not loaded'}), 404
    audits_summary = _load_audits_summary()
    server_id = request.args.get('server') or 'all'
    audits_weeks = audits_summary.get('weeks') or {}
    if server_id != 'all':
        audits_weeks = (audits_summary.get('weeks_by_server') or {}).get(server_id) or {}
    week_data = audits_weeks.get(week_start)
    if not week_data:
        return jsonify({'week': week_start, 'users': [], 'actions': {}})
    users_sorted = sorted(
        [{'user': u, 'total': t} for u, t in (week_data.get('usersCounts') or {}).items() if t > 0],
        key=lambda x: x['total'],
        reverse=True,
    )
    return jsonify({'week': week_start, 'users': users_sorted, 'actions': week_data.get('actionCounts') or {}})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
