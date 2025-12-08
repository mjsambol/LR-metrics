import requests
from typing import Any, Dict, List, Optional, Tuple
import os
import json

DEFAULT_API_BASE = "https://api.github.com"


def _headers(token: str) -> Dict[str, str]:
    h = {"Accept": "application/vnd.github+json"}
    if token:
        # Prefer Bearer for fine-grained PATs; token also works
        h["Authorization"] = f"Bearer {token}"
    return h


def parse_full_name(full: str) -> Tuple[str, str]:
    parts = (full or '').strip().split('/')
    if len(parts) != 2:
        raise ValueError("Repository must be in the form 'owner/repo'")
    return parts[0], parts[1]


def repo_exists(full_name: str, token: str, api_base: Optional[str] = None, timeout: int = 10) -> Tuple[bool, int, Any]:
    base = (api_base or DEFAULT_API_BASE).rstrip('/')
    owner, repo = parse_full_name(full_name)
    url = f"{base}/repos/{owner}/{repo}"
    resp = requests.get(url, headers=_headers(token), timeout=timeout)
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    return (resp.status_code == 200), resp.status_code, body


def list_commits(full_name: str, token: str, since_iso: Optional[str] = None, until_iso: Optional[str] = None,
                 api_base: Optional[str] = None, max_pages: int = 10, per_page: int = 100, timeout: int = 20) -> List[Dict[str, Any]]:
    base = (api_base or DEFAULT_API_BASE).rstrip('/')
    owner, repo = parse_full_name(full_name)
    url = f"{base}/repos/{owner}/{repo}/commits"
    commits: List[Dict[str, Any]] = []
    params: Dict[str, Any] = {"per_page": per_page}
    if since_iso:
        params["since"] = since_iso
    if until_iso:
        params["until"] = until_iso
    for page in range(1, max_pages + 1):
        params["page"] = page
        resp = requests.get(url, headers=_headers(token), params=params, timeout=timeout)
        if resp.status_code != 200:
            break
        try:
            batch = resp.json()
        except Exception:
            break
        if not isinstance(batch, list) or not batch:
            break
        commits.extend(batch)
        if len(batch) < per_page:
            break
    return commits


def commit_details(full_name: str, sha: str, token: str, api_base: Optional[str] = None, timeout: int = 20) -> Tuple[bool, int, Any]:
    base = (api_base or DEFAULT_API_BASE).rstrip('/')
    owner, repo = parse_full_name(full_name)
    url = f"{base}/repos/{owner}/{repo}/commits/{sha}"
    resp = requests.get(url, headers=_headers(token), timeout=timeout)
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    return (resp.status_code == 200), resp.status_code, body


def store_report(repo: Dict[str, Any], content: str, data_dir: str, ts: Optional[str] = None) -> str:
    """Persist a GitHub report JSON under data_dir/github_reports/<repo_id>/<ts>.json"""
    from datetime import datetime
    rid = repo.get('id')
    rdir = os.path.join(data_dir, 'github_reports', rid)
    os.makedirs(rdir, exist_ok=True)
    if ts is None:
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    fname = os.path.join(rdir, f"{ts}.json")
    try:
        j = json.loads(content)
        with open(fname, 'w') as f:
            json.dump(j, f, indent=2)
    except Exception:
        with open(fname, 'w') as f:
            f.write(content)
    return fname


def get_latest_report_generated_at(repo_id: str, data_dir: str) -> Optional[str]:
    """Read the latest stored report and return its generated_at ISO timestamp."""
    try:
        rdir = os.path.join(data_dir, 'github_reports', repo_id)
        if not os.path.exists(rdir):
            return None
        files = sorted([f for f in os.listdir(rdir) if f.endswith('.json')], reverse=True)
        if not files:
            return None
        latest = files[0]
        with open(os.path.join(rdir, latest), 'r') as f:
            data = json.load(f)
        gen = (data or {}).get('generated_at')
        if isinstance(gen, str) and gen:
            return gen
        return None
    except Exception:
        return None
