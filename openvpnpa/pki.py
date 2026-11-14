"""Local PKI. Client profiles require server EKU and exact server identity."""
import ipaddress
import os
import secrets
import subprocess
import threading
from pathlib import Path

from .config import hostname


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


class PKI:
    def __init__(self, root, host):
        self.root = Path(root)
        self.host = hostname(host)
        self.lock = threading.RLock()

    def initialize(self):
        with self.lock:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Never silently replace an incomplete or existing CA.
            if not (self.root/'ca.crt').exists():
                if any(self.root.iterdir()):
                    raise RuntimeError("Incomplete PKI; preserve and inspect it before retrying")
                command('openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','3650',
                    '-keyout',str(self.root/'ca.key'),'-out',str(self.root/'ca.crt'),
                    '-subj','/CN=openvpnpa-ca','-addext','basicConstraints=critical,CA:TRUE',
                    '-addext','keyUsage=critical,keyCertSign,cRLSign')
            if not (self.root/'server.crt').exists():
                try:
                    ipaddress.IPv4Address(self.host)
                    san = 'IP:'+self.host
                except ValueError:
                    san = 'DNS:'+self.host
                self.issue('server', 'openvpnpa-server', 'serverAuth', san+',IP:127.0.0.1,DNS:localhost')
            for path in self.root.glob('*.key'):
                path.chmod(0o600)

    def issue(self, stem, cn, usage, san=None):
        # Called under self.lock; caller validates UID and stem is local only.
        key, csr, cert, ext = (self.root/(stem+suffix) for suffix in ('.key','.csr','.crt','.ext'))
        command('openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(key),
            '-out',str(csr),'-subj','/CN='+cn)
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
            +'extendedKeyUsage='+usage+'\n'+('subjectAltName='+san+'\n' if san else ''))
        command('openssl','x509','-req','-in',str(csr),'-CA',str(self.root/'ca.crt'),
            '-CAkey',str(self.root/'ca.key'),'-set_serial','0x'+secrets.token_hex(16),
            '-days','365','-sha256','-extfile',str(ext),'-out',str(cert))
        key.chmod(0o600)
        csr.unlink()
        ext.unlink()

    def profile(self, uid, port, host=None):
        host = self.host if not host else hostname(host)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid profile port")
        uid = str(int(uid))
        if int(uid) < 1:
            raise ValueError("positive UID required")
        with self.lock:
            stem = 'client-'+uid
            if not (self.root/(stem+'.crt')).exists():
                self.issue(stem, uid, 'clientAuth')
            # Validate expiry: do not hand out an expired cached certificate.
            command('openssl','x509','-checkend','86400','-noout','-in',str(self.root/(stem+'.crt')))
            return ('client\ndev tun\nproto udp\nremote '+host+' '+str(port)+'\n'
                'nobind\npersist-key\npersist-tun\nremote-cert-tls server\n'
                'verify-x509-name openvpnpa-server name\n'
                'data-ciphers AES-256-GCM:AES-128-GCM\nauth-nocache\nverb 3\n'
                +''.join('<'+tag+'>\n'+(self.root/name).read_text()+'</'+tag+'>\n'
                    for tag,name in [('ca','ca.crt'),('cert',stem+'.crt'),('key',stem+'.key')]))
