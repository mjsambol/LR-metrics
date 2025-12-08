import re
import requests
from typing import Any, Dict, Optional, Tuple
from datetime import datetime

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


def get_version(base: str, timeout: int = 10, verify: bool = False) -> Tuple[int, str]:
    url = f"{base.rstrip('/')}/version"
    resp = requests.get(url, timeout=timeout, verify=verify)
    text = (resp.text or '').strip()
    if resp.status_code == 200:
        ver = re.sub(r"(?i)^\s*Lightrun Server\s*", '', text).strip()
        return resp.status_code, ver
    return resp.status_code, text[:400]


def authenticate(base: str, email: str, password: str, timeout: int = 15, verify: bool = False) -> Dict[str, Any]:
    auth_url = f"{base.rstrip('/')}/api/authenticate"
    payload = {"email": email or '', "password": password or '', "rememberMe": True}
    resp = requests.post(auth_url, json=payload, timeout=timeout, verify=verify)
    diag: Dict[str, Any] = {
        'status': resp.status_code,
        'url': auth_url,
        'payload': {k: (v if k != 'password' else '***') for k, v in payload.items()},
        'headers': dict(resp.headers),
    }
    body_json = None
    text_snippet = ''
    try:
        body_json = resp.json()
    except Exception as je:
        diag['json_error'] = str(je)
        text_snippet = (resp.text or '')[:500]
    diag['body'] = body_json if body_json is not None else text_snippet

    if resp.status_code == 200 and isinstance(body_json, dict) and 'id_token' in body_json:
        return {'ok': True, 'cookie': {'access_token': body_json.get('id_token')}, 'diag': diag}
    return {'ok': False, 'error': 'Authentication failed', 'diag': diag}


def start_diagnostics(base: str, cookie: Dict[str, str], body: Dict[str, Any], timeout: int = 20, verify: bool = False) -> Tuple[bool, int, str]:
    url = f"{base.rstrip('/')}/athena/diagnostics"
    resp = requests.post(url, json=body, cookies=cookie or {}, timeout=timeout, verify=verify)
    if resp.status_code == 200:
        return True, resp.status_code, ''
    snippet = ''
    try:
        snippet = (resp.text or '')[:300]
    except Exception:
        snippet = ''
    return False, resp.status_code, snippet


def poll_diagnostics_status(base: str, cookie: Dict[str, str], timeout: int = 20, verify: bool = False, max_iters: int = 120) -> Dict[str, Any]:
    import time
    url = f"{base.rstrip('/')}/athena/diagnostics/status"
    for _ in range(max_iters):
        resp = requests.get(url, cookies=cookie or {}, timeout=timeout, verify=verify)
        if resp.status_code != 200:
            return {'error': 'Status failed', 'status': resp.status_code}
        try:
            sj = resp.json()
        except Exception:
            return {'error': 'Invalid status payload'}
        if (sj.get('status') or '').upper() == 'COMPLETED':
            return {'status': 'COMPLETED'}
        cooldown = int(sj.get('cooldownMs') or 1000)
        time.sleep(min(max(cooldown/1000.0, 0.5), 2.0))
    return {'status': 'TIMEOUT'}


def download_diagnostics(base: str, cookie: Dict[str, str], timeout: int = 60, verify: bool = False) -> Tuple[int, Dict[str, str], bytes]:
    url = f"{base.rstrip('/')}/athena/diagnostics/download"
    resp = requests.get(url, cookies=cookie or {}, timeout=timeout, verify=verify)
    return resp.status_code, dict(resp.headers or {}), resp.content or b''


def test_connection(server: Dict[str, Any]) -> Tuple[bool, Optional[int], Any]:
    try:
        base = (server.get('url') or '').rstrip('/')
        status, ver_or_text = get_version(base, timeout=10, verify=False)
        if status == 200:
            try:
                auth = authenticate(base, server.get('email', ''), server.get('password', ''), timeout=10, verify=False)
            except Exception as e:
                auth = {'ok': False, 'error': str(e)}
            return True, status, {'version': ver_or_text, 'auth': auth}
        return False, status, ver_or_text
    except Exception as e:
        return False, None, str(e)


def diagnostics_request_body(server_name: str) -> Dict[str, Any]:
    """Standard diagnostics request body used by the app."""
    return {
        "diagnostics": [
            "KEYCLOAK", "ENVIRONMENT_VARIABLES", "FEATURE_TOGGLES", "DB_TABLES_INFO", "K8S_INFO",
            "INTEGRATIONS", "LICENSES_INFO", "USAGE_INFO", "AGENTS", "PLUGINS", "ACTIONS_INFO",
            "COMPANY_SETTINGS", "REPORT_CONFIG"
        ],
        "logCollectionSettings": {"useRandomClients": True},
        "shouldAnonymize": False,
        "reportDescription": f"{(server_name or 'server')} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    }
