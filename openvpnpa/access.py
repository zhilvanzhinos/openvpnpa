"""Access-control MODEL for compatibility tests; not an OpenVPN controller."""


class AccessModel:
    def __init__(self, tag):
        self.tag = tag
        self.allowed = set()
        self.connected = set()
        self.disconnected = set()

    def sync_user(self, user):
        # The official payload has no expiry or remaining-quota fields.
        if self.tag in user.inbounds:
            self.allowed.add(user.email)
        else:
            self.allowed.discard(user.email)
            if user.email in self.connected:
                self.connected.remove(user.email)
                self.disconnected.add(user.email)

    def connect(self, uid):
        if uid not in self.allowed:
            return False
        self.connected.add(uid)
        return True
