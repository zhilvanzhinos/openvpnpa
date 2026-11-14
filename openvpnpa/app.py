import argparse
import html
import json
import logging
import os
import secrets
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .config import load
from .panel import Panel, PanelError
from .pki import PKI
from .server import NodeHandler, UIHandler, VERSION, serve
from .state import State
from .vpn import VPN
from . import service_pb2 as pb

log = logging.getLogger(__name__)


class App:
    def __init__(self, config, root):
        self.config = config
        self.root = Path(root)
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.pki = PKI(self.root/'pki',config['public_host'])
        self.state = State(self.root/'state.sqlite',config['inbound_tag'],config['lease_seconds'])
        config['group_ids'] = self.state.setting('group_ids',config['group_ids'])
        self.panel = Panel(config)
        self.profile_endpoint = self.state.setting('profile_endpoint', {'host':'', 'port':None})
        self.vpn = VPN(config,self.state,self.root)
        self.boot = time.monotonic()
        self.control = threading.RLock()
        self.refresh_lock = threading.Lock()
        self.csrf = secrets.token_urlsafe(32)
        self.stopping = threading.Event()
        self.servers = []

    def info(self):
        return pb.BaseInfoResponse(started=self.state.started and self.vpn.ready.is_set() and not self.vpn.failed.is_set(),
            node_version=VERSION,core_version='OpenVPN-2.6')

    def core_template(self):
        return {'name':'OpenVPNPA dedicated marker','type':'xray','config':{
            'inbounds':[{'tag':self.config['inbound_tag'],'listen':'127.0.0.1','port':19090,
                'protocol':'vless','settings':{'clients':[],'decryption':'none'}}],
            'outbounds':[{'protocol':'freedom','tag':'openvpn-egress'}]},
            'exclude_inbound_tags':[],'fallbacks_inbound_tags':[]}

    def connection_page(self):
        config = self.config
        descriptor = {'name':'OpenVPNPA','address':config['public_host'],
            'port':config['node_port'],'api_port':config['node_port'],'connection_type':'rest',
            'usage_coefficient':1,'keep_alive':60,'core_config_id':'REPLACE_WITH_NEW_CORE_ID',
            'api_key':config['node_api_key'],'server_ca':(self.pki.root/'ca.crt').read_text()}
        text = ('<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><title>اتصال نود</title>'
            '<h1>افزودن نود اختصاصی در پاسارگارد</h1><p>در پاسارگارد یک Core جدید با تنظیم زیر بسازید؛ '
            'این تنظیم Xray اجرا نمی‌کند و فقط برای انتخاب کاربران این نود است. به Core یا نود فعلی دست نزنید.</p>'
            '<pre dir="ltr">'+html.escape(json.dumps(self.core_template(),indent=2))+'</pre>'
            '<p>سپس نود جدید را با مقادیر زیر ثبت کنید و شناسه Core جدید را جایگزین کنید. '
            'api_port عمداً با port برابر است؛ قابلیت بروزرسانی از پنل پشتیبانی نمی‌شود.</p>'
            '<pre dir="ltr">'+html.escape(json.dumps(descriptor,indent=2))+'</pre>'
            '<p>یک گروه اختصاصی بسازید که فقط inbound با tag '+html.escape(config['inbound_tag'])+
            ' را داشته باشد. شناسه گروه را در فرم زیر ذخیره کنید. '
            'برای کاربر مشترک V2Ray، گروه OpenVPN را در کنار گروه‌های فعلی او اضافه کنید.</p>'
            '<p>پورت UDP پروفایل: '+str(config['vpn_port'])+'؛ پورت TCP نود: '+str(config['node_port'])+
            '. کلید API فقط برای مدیر است. پنل فعال در این مرحله خودکار تغییر داده نمی‌شود.</p>'
            '<form action="/settings/groups" method="post"><input type="hidden" name="csrf" value="'+self.csrf+'">'
            '<label>شناسه گروه‌های اختصاصی، جداشده با کاما: <input name="group_ids" value="'
            +','.join(str(i) for i in config['group_ids'])+'" required></label><button>ذخیره در این سرویس</button></form>'
            '<a href="/">بازگشت</a></html>')
        return text

    def refresh(self):
        # Avoid concurrent refresh loops from UI and scheduler.
        if not self.refresh_lock.acquire(blocking=False):
            return
        try:
            imported = set()
            try:
                for user in self.panel.users():
                    self.state.enroll(user)
                    imported.add(str(int(user['id'])))
            except (PanelError, ValueError, KeyError, TypeError):
                log.warning('Panel user import failed; existing users will be refreshed individually')
            def refresh_user(user):
                try:
                    fresh = self.panel.get_user(user['id'])
                    if int(fresh['id'])!=int(user['id']):
                        raise ValueError('panel UID mismatch')
                    self.state.cache_user(fresh)
                except (PanelError,ValueError,KeyError):
                    # Never refresh freshness on failure; authorization expires.
                    log.warning('Panel user refresh failed for UID %s; access cache will expire',user['id'])
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(refresh_user,(user for user in self.state.users()
                    if str(user['id']) not in imported)))
        finally:
            self.refresh_lock.release()

    def enforce(self):
        if self.state.started and time.monotonic()-self.state.last_request>self.state.lease:
            self.state.stop()
        with self.vpn.management.lock:
            uids = {data['uid'] for data in self.vpn.management.clients.values()}
        for uid in uids:
            if not self.state.authorized(uid):
                self.vpn.management.kill(uid)

    def run(self):
        self.pki.initialize()
        self.vpn.start()
        try:
            self.servers = [serve(self,('0.0.0.0',62050),NodeHandler),serve(self,('0.0.0.0',8443),UIHandler)]
            def update():
                while not self.stopping.is_set():
                    self.refresh()
                    self.stopping.wait(15)
            updater = threading.Thread(target=update,daemon=True)
            updater.start()
            log.info('Management UI and REST node are listening; waiting for PasarGuard Start')
            while not self.stopping.wait(.5):
                if self.vpn.failed.is_set() or self.vpn.process.poll() is not None:
                    raise RuntimeError('OpenVPN or accounting channel failed; stopping service')
                self.enforce()
        finally:
            self.stopping.set()
            self.state.stop()
            for server,thread in self.servers:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
            self.vpn.stop()
            if 'updater' in locals():
                updater.join(timeout=12)
            self.state.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config',default='/config/config.json')
    parser.add_argument('--state',default='/var/lib/openvpnpa')
    parser.add_argument('--init',action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    config = load(args.config)
    if args.init:
        PKI(Path(args.state)/'pki',config['public_host']).initialize()
        print('PKI initialized; private keys remain in the persistent state directory')
        return
    # NAT is scoped to this container namespace, never the host firewall.
    subprocess.run(['iptables','-t','nat','-A','POSTROUTING','-s',config['vpn_network'],
        '-o','eth0','-j','MASQUERADE'],check=True)
    subprocess.run(['iptables','-A','FORWARD','-i','tun0','-o','tun0','-j','DROP'],check=True)
    subprocess.run(['iptables','-A','FORWARD','-i','tun0','-o','eth0','-j','ACCEPT'],check=True)
    subprocess.run(['iptables','-A','FORWARD','-i','eth0','-o','tun0','-m','conntrack',
        '--ctstate','RELATED,ESTABLISHED','-j','ACCEPT'],check=True)
    app = App(config,args.state)
    def stop(*_):
        app.stopping.set()
    signal.signal(signal.SIGTERM,stop)
    signal.signal(signal.SIGINT,stop)
    app.run()


if __name__=='__main__':
    main()
