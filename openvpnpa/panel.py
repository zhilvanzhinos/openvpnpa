"""Official management API only. Traffic is NEVER written through this API."""
import json
import ssl
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class PanelError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise PanelError("Panel redirect refused; configure the final HTTPS base URL")


class Panel:
    def __init__(self, config):
        self.config = config
        context = ssl.create_default_context(cafile=config.get("panel_ca") or None)
        self.client = build_opener(NoRedirect(), HTTPSHandler(context=context))

    def login(self, username, password):
        req = Request(self.config['panel_url']+'/api/admin/token',
            data=urlencode({'username':username,'password':password}).encode(),
            headers={'Content-Type':'application/x-www-form-urlencoded'},method='POST')
        data = self.exchange(req)
        token = data.get('access_token') if isinstance(data,dict) else None
        if not isinstance(token,str) or not token or '\n' in token or '\r' in token:
            raise PanelError('PasarGuard did not return a valid access token')
        self.config['panel_token'] = token
        return token

    def request(self, method, path, body=None):
        token = self.config.get("panel_token", "")
        if not token:
            raise PanelError("PasarGuard API token is not configured")
        req = Request(self.config["panel_url"]+path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": "Bearer "+token, "Content-Type": "application/json"}, method=method)
        return self.exchange(req)

    def exchange(self, req):
        try:
            with self.client.open(req, timeout=10) as response:
                payload = response.read(4*1024*1024+1)
                if len(payload) > 4*1024*1024:
                    raise PanelError("Panel response too large")
                return json.loads(payload)
        except HTTPError as error:
            # Never echo remote error text, submitted credentials or headers.
            raise PanelError(f"PasarGuard API returned HTTP {error.code}") from None
        except (URLError, ValueError, TimeoutError):
            raise PanelError("PasarGuard API unavailable or returned invalid JSON") from None

    def users(self, page_size=100):
        """Read every API page, without creating users or changing groups.

        PasarGuard 5.5.1 supports offset/limit and username sorting. Advance
        by the actual page length because servers may cap the requested limit.
        Reject non-progressing/malformed pages rather than loop forever.
        """
        offset, seen = 0, set()
        while True:
            page = self.request("GET", "/api/users?"+urlencode(
                dict(offset=offset, limit=page_size, sort="username")))
            if not isinstance(page, dict) or not isinstance(page.get('users'), list):
                raise PanelError("Invalid users page")
            total = page.get('total')
            if type(total) is not int or total < 0:
                raise PanelError("Invalid users total")
            users = page['users']
            if not users:
                if offset < total:
                    raise PanelError("Incomplete users page")
                return
            try:
                ids = {int(user['id']) for user in users}
                if any(uid < 1 for uid in ids):
                    raise ValueError()
            except (KeyError, TypeError, ValueError):
                raise PanelError("Invalid users page UID") from None
            if not ids-seen:
                raise PanelError("Users pagination made no progress")
            seen.update(ids)
            yield from users
            offset += len(users)
            if offset >= total:
                return

    def get_user(self, uid):
        return self.request("GET", "/api/user/by-id/"+str(int(uid)))

    def find_user(self, username):
        return self.request("GET", "/api/user/by-username/"+quote(username, safe=''))

    def create(self, username, gib, days):
        if not self.config["group_ids"]:
            raise PanelError("Configure the dedicated OpenVPN group IDs before creating users")
        return self.request("POST", "/api/user", {
            "username": username, "status": "active", "group_ids": self.config["group_ids"],
            "proxy_settings": {}, "data_limit": int(gib*1024**3),
            "expire": int(datetime.now(timezone.utc).timestamp())+days*86400 if days else 0,
            "data_limit_reset_strategy": "no_reset"})


def active(user, now=None):
    """Mirror the panel decision conservatively; never maintain another quota."""
    if user.get("status") != "active":
        return False
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    expiry = user.get("expire")
    if expiry:
        if isinstance(expiry, str):
            expiry = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
            if expiry.tzinfo is None:
                raise ValueError("panel expiry must include timezone")
            expiry = expiry.timestamp()
        if float(expiry) <= now:
            return False
    limit = int(user.get("data_limit") or 0)
    return not limit or int(user.get("used_traffic") or 0) < limit
