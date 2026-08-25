import urllib.error
import urllib.request
from urllib.parse import quote


def http_get(target, path="/", timeout=5.0, headers=None):
    if not path.startswith("/"):
        path = "/" + path
    url = f"{target.base_url}{quote(path, safe='/%;:?&=#@')}"
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {
                "status": response.status,
                "headers": dict(response.headers.items()),
                "body": response.read(),
            }
    except urllib.error.HTTPError as exc:
        return {
            "status": exc.code,
            "headers": dict(exc.headers.items()),
            "body": exc.read() if exc.fp else b"",
        }
    except (urllib.error.URLError, OSError, ValueError):
        return None
