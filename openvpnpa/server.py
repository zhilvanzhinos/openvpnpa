"""TLS management UI and PasarGuard REST/protobuf adapter on separate ports."""
import base64
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import socket
import ssl
import threading
import time
from decimal import Decimal, InvalidOperation
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from google.protobuf.message import DecodeError

from . import service_pb2 as pb
from .panel import PanelError, active
from .config import hostname

VERSION = '0.2.0-beta.9'
MAX_BODY = 4*1024*1024
log = logging.getLogger(__name__)


def decode_chunks(data):
    """Protobuf varint frames used by official SyncUsersChunked (partial sync)."""
    offset,expected,users,saw_last = 0,0,[],False
    while offset < len(data):
        size,shift = 0,0
        while True:
            if offset >= len(data) or shift >= 35:
                raise ValueError('invalid protobuf frame length')
            byte = data[offset]
            offset += 1
            size |= (byte & 127)<<shift
            if not byte & 128:
                break
            shift += 7
        if not size or offset+size > len(data):
            raise ValueError('truncated protobuf frame')
        chunk = pb.UsersChunk.FromString(data[offset:offset+size])
        offset += size
        if saw_last or chunk.index != expected:
            raise ValueError('unordered or trailing user chunk')
        expected += 1
        users.extend(chunk.users)
        saw_last = chunk.last
    if not saw_last:
        raise ValueError('missing final user chunk')
    return users


class HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address,handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request,address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request,address)
        finally:
            self.slots.release()

    def get_request(self):
        connection,address = self.socket.accept()
        connection.settimeout(10)
        try:
            return self.tls.wrap_socket(connection,server_side=True),address
        except BaseException:
            connection.close()
            raise


class Handler(BaseHTTPRequestHandler):
    server_version = 'openvpnpa'

    def log_message(self, *_args):
        # No profile URLs, Authorization headers, remote payloads or credentials.
        pass

    def reply(self, code, data=b'', kind='application/json', headers=None):
        self.send_response(code)
        self.send_header('Content-Type',kind)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        for key,value in (headers or {}).items():
            self.send_header(key,value)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        transfer = self.headers.get('Transfer-Encoding','').lower()
        length = self.headers.get('Content-Length')
        if transfer:
            if transfer != 'chunked' or length is not None:
                raise ValueError('unsupported request framing')
            data = bytearray()
            while True:
                line = self.rfile.readline(66)
                if len(line)>65 or not re.fullmatch(rb'[0-9a-fA-F]+\r\n',line):
                    raise ValueError('invalid HTTP chunk')
                size = int(line,16)
                if not size:
                    if self.rfile.readline(3) != b'\r\n':
                        raise ValueError('HTTP trailers unsupported')
                    return bytes(data)
                if len(data)+size > MAX_BODY:
                    raise ValueError('body too large')
                block = self.rfile.read(size)
                if len(block)!=size or self.rfile.read(2)!=b'\r\n':
                    raise ValueError('truncated HTTP chunk')
                data.extend(block)
        size = int(length or 0)
        if size<0 or size>MAX_BODY:
            raise ValueError('body too large')
        data = self.rfile.read(size)
        if len(data)!=size:
            raise ValueError('truncated body')
        return data

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def do_PUT(self):
        self.dispatch()

    def dispatch(self):
        try:
            self.handle_route()
        except (ValueError,KeyError,DecodeError,InvalidOperation):
            self.reply(400,b'{"error":"invalid request"}')
        except PanelError as error:
            self.reply(502,json.dumps({'error':str(error)}).encode())
        except (BrokenPipeError,ConnectionResetError,socket.timeout):
            pass
        except Exception:
            log.exception('Local request failed')
            self.reply(500,b'{"error":"local operation failed; inspect server logs"}')


class NodeHandler(Handler):
    def proto(self, response):
        self.reply(200,response.SerializeToString(),'application/x-protobuf')

    def handle_route(self):
        app = self.server.app
        if not hmac.compare_digest(self.headers.get('x-api-key',''),app.config['node_api_key']):
            self.reply(401,b'{"error":"unauthorized"}')
            return
        state = app.state
        # A late heartbeat must not revive an expired lease without a fresh
        # Start/full permission snapshot, even between supervisor ticks.
        app.enforce()
        route = self.command,urlsplit(self.path).path
        if route == ('GET','/info'):
            state.touch()
            self.proto(app.info())
            return
        if route == ('POST','/start'):
            backend = pb.Backend.FromString(self.body())
            descriptor = json.loads(backend.config)
            if backend.type != pb.XRAY or not any(i.get('tag')==state.tag for i in descriptor.get('inbounds',[])) or state.tag in backend.exclude_inbounds:
                raise ValueError('dedicated OpenVPN inbound tag required')
            # Match official Start-or-attach: a heartbeat must not erase users.
            with app.control:
                if not state.started or state.last_start_config != backend.config:
                    state.synced(backend.users,full=True)
                state.last_start_config = backend.config
                state.started = True
                state.touch()
            self.proto(app.info())
            return
        if route == ('PUT','/stop'):
            state.stop()
            state.touch()
            self.proto(pb.Empty())
            return
        if not state.started or not app.vpn.ready.is_set() or app.vpn.failed.is_set():
            self.reply(503,b'{"error":"core is not started yet"}')
            return
        if route == ('PUT','/user/sync'):
            users,full = [pb.User.FromString(self.body())],False
        elif route == ('PUT','/users/sync'):
            users,full = pb.Users.FromString(self.body()).users,True
        elif route == ('PUT','/users/sync/chunked'):
            users,full = decode_chunks(self.body()),False
        else:
            users = None
        if users is not None:
            with app.control:
                state.synced(users,full=full)
            state.touch()
            self.proto(pb.Empty())
            return
        if route in (('GET','/stats'),('GET','/stats/')):
            request = pb.StatRequest.FromString(self.body())
            if request.type == pb.UsersStat:
                stats = state.stats(reset=request.reset)
            elif request.type == pb.UserStat:
                stats = state.stats(reset=request.reset,uid=request.name)
            elif request.type in (pb.Outbounds,pb.Outbound):
                stats = state.outbound_stats(request.reset) if not request.name or request.name=='openvpn-egress' else []
            elif request.type in (pb.Inbounds,pb.Inbound):
                stats = []  # never report the user delta a second time
            else:
                raise ValueError('unknown stat type')
            state.touch()
            self.proto(pb.StatResponse(stats=[pb.Stat(**item) for item in stats]))
            return
        if route == ('GET','/stats/backend'):
            state.touch()
            self.proto(pb.BackendStatsResponse(uptime=int(time.monotonic()-app.boot)))
            return
        if route == ('GET','/stats/system'):
            state.touch()
            self.proto(pb.SystemStatsResponse(cpu_cores=os.cpu_count() or 1,uptime=int(time.monotonic()-app.boot)))
            return
        if route in [('GET','/stats/user/online'),('GET','/stats/user/online_ip')]:
            request = pb.StatRequest.FromString(self.body())
            online = app.vpn.management.online(request.name)
            state.touch()
            self.proto(pb.OnlineStatResponse(name=request.name,value=len(online)) if route[1].endswith('/online') else
                pb.StatsOnlineIpListResponse(name=request.name,ips={item['ip']:1 for item in online if item['ip']}))
            return
        if route == ('GET','/stats/latency'):
            state.touch()
            self.proto(pb.LatencyResponse())
            return
        self.reply(501,b'{"error":"unsupported operation; no Xray backend or remote updater"}')


STYLE = 'body{font:16px system-ui;background:#101827;color:#e2e8f0;max-width:1000px;margin:40px auto;padding:20px}input,button{font:inherit;padding:9px;margin:5px;border-radius:6px}section{background:#1e293b;padding:18px;margin:18px 0;border-radius:12px}table{width:100%;border-collapse:collapse}td,th{padding:10px;text-align:right;border-bottom:1px solid #475569}a{color:#7dd3fc}small{color:#cbd5e1}'


class UIHandler(Handler):
    def authenticate(self):
        app = self.server.app
        try:
            scheme,token = self.headers.get('Authorization','').split(' ',1)
            if scheme.lower()!='basic':
                raise ValueError()
            raw = base64.b64decode(token,validate=True)
            candidate = hashlib.sha256(raw).digest()
            expected = hashlib.sha256((app.config['admin_user']+':'+app.config['admin_password']).encode()).digest()
            valid = hmac.compare_digest(candidate,expected)
        except ValueError:
            valid = False
        if not valid:
            time.sleep(.2)
            self.reply(401,b'{"error":"authentication required"}',headers={'WWW-Authenticate':'Basic realm="OpenVPNPA", charset="UTF-8"'})
        return valid

    def handle_route(self):
        app = self.server.app
        path = urlsplit(self.path).path
        if self.command=='GET' and path=='/health':
            ok = app.vpn.ready.is_set() and not app.vpn.failed.is_set()
            self.reply(200 if ok else 503,json.dumps({'ok':ok}).encode())
            return
        if not self.authenticate():
            return
        if self.command=='GET' and path=='/':
            self.index()
            return
        if self.command=='GET' and re.fullmatch(r'/profiles/[1-9][0-9]*\.ovpn',path):
            uid = path.split('/')[-1].split('.')[0]
            if not any(str(user['id'])==uid for user in app.state.users()):
                self.reply(404,b'{"error":"user is not enrolled"}')
                return
            user = app.panel.get_user(uid)
            app.state.cache_user(user)
            if not active(user):
                self.reply(403,b'{"error":"user is not active in PasarGuard"}')
                return
            endpoint = app.profile_endpoint
            data = app.pki.profile(uid,endpoint['port'] or app.config['vpn_port'],endpoint['host']).encode()
            self.reply(200,data,'application/x-openvpn-profile',{'Content-Disposition':f'attachment; filename="openvpn-{uid}.ovpn"'})
            return
        if self.command=='GET' and path=='/setup':
            self.reply(200,app.connection_page().encode(),'text/html; charset=utf-8')
            return
        if self.command!='POST':
            self.reply(404,b'{"error":"not found"}')
            return
        form = parse_qs(self.body().decode(),keep_blank_values=True,max_num_fields=10)
        if not hmac.compare_digest(form.get('csrf',[''])[0],app.csrf):
            self.reply(403,b'{"error":"invalid CSRF token"}')
            return
        if path in ('/users/create','/users/attach'):
            username = form['username'][0]
            if not re.fullmatch(r'[a-z0-9_]{3,32}',username):
                raise ValueError('invalid username')
            if path.endswith('/create'):
                gib = Decimal(form['gib'][0])
                days = int(form['days'][0])
                if not gib.is_finite() or not 0<=gib<=1000000 or not 0<=days<=3650:
                    raise ValueError('invalid limits')
                user = app.panel.create(username,gib,days)
            else:
                user = app.panel.find_user(username)
            app.state.enroll(user)
        elif path=='/refresh':
            app.refresh()
        elif path=='/settings/profile':
            host = form.get('host',[''])[0].strip()
            port_text = form.get('port',[''])[0].strip()
            if host:
                hostname(host)
            port = int(port_text) if port_text else None
            if port is not None and not 1 <= port <= 65535:
                raise ValueError('invalid profile port')
            endpoint = {'host':host, 'port':port}
            app.state.save_setting('profile_endpoint',endpoint)
            app.profile_endpoint = endpoint
        elif path=='/settings/groups':
            values = form['group_ids'][0].split(',')
            ids = list(dict.fromkeys(int(value.strip()) for value in values))
            if not ids or len(ids)>100 or any(value<1 for value in ids):
                raise ValueError('positive group IDs required')
            app.state.save_setting('group_ids',ids)
            app.config['group_ids'] = ids
        else:
            self.reply(404,b'{"error":"not found"}')
            return
        self.reply(303,headers={'Location':'/'})

    def index(self):
        app = self.server.app
        esc = html.escape
        token = '<input type="hidden" name="csrf" value="'+app.csrf+'">'
        rows = ''.join('<tr><td>'+esc(user['username'])+'</td><td>'+str(user['id'])+'</td><td>'
            +esc(str(user['status']))+'</td><td>'+str(round((user.get('used_traffic') or 0)/1024**3,3))
            +'</td><td>'+('مجاز' if app.state.authorized(str(user['id'])) else 'بسته / منتظر همگام‌سازی')
            +'</td><td><a href="/profiles/'+str(int(user['id']))+'.ovpn">دانلود ovpn</a></td></tr>'
            for user in app.state.users())
        bound = app.state.started and time.monotonic()-app.state.last_request<=app.state.lease
        body = ('<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><title>OpenVPNPA</title><style>'+STYLE+'</style>'
            '<h1>مدیریت OpenVPN</h1><p>اتصال نود به پاسارگارد: '+('برقرار' if bound else 'منتظر اتصال')
            +' · <a href="/setup">تنظیمات اتصال نود</a></p>'
            '<section><h2>آدرس اتصال کلاینت OpenVPN</h2><form method="post" action="/settings/profile">'+token+
            '<label>IP یا دامنه تانل <input name="host" dir="ltr" value="'+esc(app.profile_endpoint['host'],quote=True)+'"></label>'
            '<label>پورت اتصال UDP <input name="port" type="number" min="1" max="65535" value="'
            +str(app.profile_endpoint['port'] or '')+'"></label><button>ذخیره</button></form>'
            '<small>مقدار خالی: آدرس اصلی نود و پورت اصلی OpenVPN. فقط remote فایل‌های جدید تغییر می‌کند؛ '
            'فایل‌های قبلی و ارتباط پاسارگارد تغییر نمی‌کنند. تانل باید UDP را منتقل کند.</small></section>'
            '<section><h2>ساخت کاربر در پاسارگارد</h2><form method="post" action="/users/create">'+token+
            '<input name="username" placeholder="نام کاربری" pattern="[a-z0-9_]{3,32}" required>'
            '<input name="gib" type="number" min="0" max="1000000" step="0.01" value="10" aria-label="حجم گیگابایت">'
            '<input name="days" type="number" min="0" max="3650" value="30" aria-label="مدت روز">'
            '<button>ساخت کاربر</button></form><small>حجم برحسب GiB و مدت برحسب روز؛ صفر یعنی نامحدود. سهمیه در پاسارگارد ثبت می‌شود.</small></section>'
            '<section><h2>اتصال کاربر موجود</h2><form method="post" action="/users/attach">'+token+
            '<input name="username" placeholder="نام کاربری پاسارگارد" required><button>افزودن به این نود</button></form>'
            '<small>کاربر باید در پاسارگارد عضو گروه اختصاصی این نود باشد. این عملیات گروه‌های او را تغییر نمی‌دهد.</small></section>'
            '<section><form method="post" action="/refresh">'+token+'<button>تازه‌سازی وضعیت از پاسارگارد</button></form>'
            '<table><tr><th>کاربر</th><th>UID</th><th>وضعیت پنل</th><th>مصرف مشترک GiB</th><th>دسترسی نود</th><th>پروفایل</th></tr>'
            +rows+'</table></section><small>فایل ovpn حاوی کلید خصوصی کاربر است. قطع دسترسی تابع تصمیم پاسارگارد و زمان همگام‌سازی است.</small></html>')
        self.reply(200,body.encode(),'text/html; charset=utf-8')


def serve(app, address, handler):
    server = HTTPServer(address,handler)
    server.app = app
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(['http/1.1'])
    context.load_cert_chain(app.pki.root/'server.crt',app.pki.root/'server.key')
    server.tls = context
    thread = threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    return server,thread
