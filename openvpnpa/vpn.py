"""One supervised OpenVPN process and its private Unix management socket."""
import ipaddress
import logging
import os
import socket
import subprocess
import threading
import time
from pathlib import Path
from uuid import uuid4

log = logging.getLogger(__name__)


class Management:
    def __init__(self, state, epoch):
        self.state, self.epoch = state, epoch
        self.clients = {}
        self.lock = threading.RLock()
        self.event = None
        self.send = lambda command: None

    def kill(self, uid):
        with self.lock:
            ids = [cid for cid,data in self.clients.items() if data['uid'] == uid]
        for cid in ids:
            self.send(f'client-kill {cid} "access revoked"')

    def online(self, uid):
        with self.lock:
            return [data.copy() for data in self.clients.values() if data['uid']==uid and data.get('established')]

    def line(self, line):
        if line.startswith('>BYTECOUNT_CLI:'):
            cid,up,down = line.partition(':')[2].split(',')
            with self.lock:
                data = self.clients.get(cid)
            if data:
                self.state.sample(self.epoch,cid,data['uid'],int(up),int(down))
            return
        if not line.startswith('>CLIENT:'):
            return
        value = line[len('>CLIENT:'):]
        kind,_,rest = value.partition(',')
        if kind == 'ENV':
            if self.event is None:
                return
            if rest == 'END':
                event,self.event = self.event,None
                self.apply(*event)
            else:
                name,_,val = rest.partition('=')
                # Do not retain passwords or unbounded environment data.
                if name in {'common_name','trusted_ip','bytes_received','bytes_sent'}:
                    self.event[2][name] = val
        elif kind in {'CONNECT','REAUTH','ESTABLISHED','DISCONNECT'}:
            self.event = [kind,rest.split(','),{}]

    def apply(self, kind, args, env):
        cid = args[0]
        if not cid.isdecimal():
            raise ValueError('invalid management client ID')
        if kind in {'CONNECT','REAUTH'}:
            kid = args[1]
            uid = env.get('common_name','')
            if not kid.isdecimal():
                raise ValueError('invalid management key ID')
            if not uid.isascii() or not uid.isdecimal() or not self.state.authorized(uid):
                self.send(f'client-deny {cid} {kid} "access denied"')
                return
            with self.lock:
                previous = self.clients.get(cid)
                if previous and previous['uid'] != uid:
                    raise ValueError('management session changed owner')
                if not previous:
                    self.clients[cid] = dict(uid=uid,ip=env.get('trusted_ip',''),established=False)
            self.send(f'client-auth-nt {cid} {kid}')
        elif kind == 'ESTABLISHED':
            with self.lock:
                if cid in self.clients:
                    self.clients[cid]['established'] = True
        elif kind == 'DISCONNECT':
            with self.lock:
                data = self.clients.get(cid)
            if data:
                self.state.sample(self.epoch,cid,data['uid'],int(env['bytes_received']),int(env['bytes_sent']),final=True)
                with self.lock:
                    self.clients.pop(cid,None)


class VPN:
    def __init__(self, config, state, root):
        self.config,self.state,self.root = config,state,Path(root)
        self.management = Management(state,str(uuid4()))
        self.state.revoke = self.management.kill
        self.ready = threading.Event()
        self.failed = threading.Event()
        self.stopping = threading.Event()
        self.write_lock = threading.Lock()
        self.process = None
        self.sock = None

    def start(self):
        runtime = self.root/'run'
        runtime.mkdir(mode=0o700,exist_ok=True)
        sock = runtime/'management.sock'
        sock.unlink(missing_ok=True)
        net = ipaddress.IPv4Network(self.config['vpn_network'])
        pki = self.root/'pki'
        conf = ('dev tun\nproto udp\nport 1194\ntopology subnet\n'
            f'server {net.network_address} {net.netmask}\n'
            f'ca {pki}/ca.crt\ncert {pki}/server.crt\nkey {pki}/server.key\n'
            'dh none\nverify-client-cert require\nremote-cert-tls client\n'
            'tls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM\n'
            f'management {sock} unix\nmanagement-client-auth\nmanagement-hold\n'
            'management-log-cache 1\nkeepalive 10 60\nexplicit-exit-notify 1\n'
            'push "redirect-gateway def1"\npush "dhcp-option DNS 1.1.1.1"\n'
            'push "block-ipv6"\npersist-key\npersist-tun\nverb 3\n')
        (runtime/'server.conf').write_text(conf)
        self.logfile = (runtime/'openvpn.log').open('w')
        self.process = subprocess.Popen(['openvpn','--config',str(runtime/'server.conf')],stdout=self.logfile,stderr=subprocess.STDOUT)
        self.thread = threading.Thread(target=self.run,daemon=True)
        self.thread.start()
        deadline = time.monotonic()+12
        while not self.ready.wait(.1) and not self.failed.is_set() and self.process.poll() is None and time.monotonic()<deadline:
            pass
        if not self.ready.is_set():
            self.stop()
            raise RuntimeError('OpenVPN management did not become ready; inspect the local OpenVPN log')

    def run(self):
        try:
            deadline = time.monotonic()+10
            while not (self.root/'run/management.sock').exists():
                if self.process.poll() is not None or time.monotonic()>deadline:
                    raise RuntimeError('OpenVPN exited before management started')
                time.sleep(.05)
            self.sock = socket.socket(socket.AF_UNIX)
            self.sock.connect(str(self.root/'run/management.sock'))
            self.management.send = self.send
            self.send('state on')
            self.send('bytecount 1')
            self.send('hold release')
            with self.sock.makefile('r',encoding='utf-8',errors='strict') as stream:
                while line := stream.readline(65537):
                    if len(line)>65536:
                        raise ValueError('oversized management event')
                    line = line.rstrip('\r\n')
                    if line.startswith('>STATE:'):
                        fields = line.partition(':')[2].split(',')
                        if len(fields)>2 and fields[1:3]==['CONNECTED','SUCCESS']:
                            self.ready.set()
                    self.management.line(line)
            if not self.stopping.is_set():
                raise RuntimeError('OpenVPN management disconnected')
        except Exception:
            if not self.stopping.is_set():
                log.exception('OpenVPN management failed; stopping unmetered service')
                self.failed.set()

    def send(self, command):
        with self.write_lock:
            if not self.sock:
                raise RuntimeError('management unavailable')
            self.sock.sendall(command.encode()+b'\n')

    def stop(self):
        self.stopping.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        if self.sock:
            self.sock.close()
        if hasattr(self,'thread'):
            self.thread.join(timeout=3)
        if hasattr(self,'logfile'):
            self.logfile.close()
