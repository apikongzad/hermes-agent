"""Two probe contracts. No fallback. No credentialed retry."""

DEFAULT_PROBE_TIMEOUT_MS = 15000

DASHBOARD_URL = "http://127.0.0.1:9119/api/health"
DASHBOARD_TIMEOUT_S = 15.0

GATEWAY_REQUEST_BYTES = b'{"verb":"identify","id":1,"protocol":1}\n'
GATEWAY_TIMEOUT_S = 2.0


def dashboard_ok(status, content_type, body):
    if status != 200:
        return False
    ctype = (content_type or "").lower()
    if "application/json" not in ctype:
        return False
    if not isinstance(body, dict):
        return False
    return body.get("ok") is True


def gateway_ok(response, peer_pid, peer_uid, expected_pid):
    if not isinstance(response, dict):
        return False
    if response.get("ok") is not True:
        return False
    result = response.get("result")
    if not isinstance(result, dict):
        return False
    if result.get("protocol") != 1:
        return False
    if result.get("pid") != expected_pid:
        return False
    if peer_pid != expected_pid:
        return False
    if peer_uid != 1001:
        return False
    return True
