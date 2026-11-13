"""Real TLS UI + REST/protobuf + mock PasarGuard management API integration.

Management events are fixtures from the documented OpenVPN protocol. This suite
does not claim to create a kernel TUN or run the complete upstream panel.
"""
import base64
import http.client
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

from openvpnpa import service_pb2 as pb
from openvpnpa.app import App
from openvpnpa.config import load
from openvpnpa.panel import Panel, PanelError
from openvpnpa.pki import PKI
from openvpnpa.server import Handler, NodeHandler, UIHandler, serve
from openvpnpa.setup import write_config
from openvpnpa.state import State
from openvpnpa.vpn import VPN


@unittest.skipUnless(shutil.which('openssl'),'openssl required')
class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.base = dict(public_host='127.0.0.1',panel_url='https://127.0.0.1',panel_token='lab-token',
            admin_user='admin',admin_password='lab-password-for-test-only',node_api_key=str(uuid4()),
            inbound_tag='openvpnpa',group_ids=[7],lease_seconds=120,vpn_network='10.89.0.0/24',
            ui_port=8443,node_port=62050,vpn_port=1194)
        cls.pki = PKI(cls.root/'pki','127.0.0.1')
        cls.pki.initialize()
        cls.context = ssl.create_default_context(cafile=str(cls.pki.root/'ca.crt'))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.case_tmp = tempfile.TemporaryDirectory(dir=self.root)
        self.app = App(dict(self.base),self.case_tmp.name)
        self.app.pki = self.pki
        self.sent = []
        self.app.vpn.ready.set()
        self.app.vpn.management.send = self.sent.append
        self.panel_users = {}
        self.api_calls = []
        test = self

        class PanelMock(Handler):
            def handle_route(self):
                test.api_calls.append((self.command,self.path))
                if self.headers.get('Authorization')!='Bearer lab-token':
                    self.reply(401,b'{}')
                    return
                if self.command=='POST' and self.path=='/api/user':
                    data = json.loads(self.body())
                    if any(user['username']==data['username'] for user in test.panel_users.values()):
                        self.reply(409,b'{}')
                        return
                    user = dict(data,id=len(test.panel_users)+42,used_traffic=0)
                    test.panel_users[user['id']] = user
                elif self.command=='GET' and self.path.startswith('/api/user/by-id/'):
                    user = test.panel_users.get(int(self.path.rsplit('/',1)[1]))
                elif self.command=='GET' and self.path.startswith('/api/user/by-username/'):
                    user = next((u for u in test.panel_users.values() if u['username']==self.path.rsplit('/',1)[1]),None)
                else:
                    self.reply(404,b'{}')
                    return
                if not user:
                    self.reply(404,b'{}')
                else:
                    self.reply(200,json.dumps(user).encode())

        self.panel_server,self.panel_thread = serve(self.app,('127.0.0.1',0),PanelMock)
        self.app.config['panel_url']='https://127.0.0.1:'+str(self.panel_server.server_port)
        self.app.config['panel_ca']=str(self.pki.root/'ca.crt')
        self.app.panel = Panel(self.app.config)
        self.node,self.node_thread = serve(self.app,('127.0.0.1',0),NodeHandler)
        self.ui,self.ui_thread = serve(self.app,('127.0.0.1',0),UIHandler)

    def tearDown(self):
        for server,thread in [(self.node,self.node_thread),(self.ui,self.ui_thread),(self.panel_server,self.panel_thread)]:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        self.app.state.close()
        self.case_tmp.cleanup()

    def request(self, server, method, path, body=None, headers=None, *, chunked=False):
        client = http.client.HTTPSConnection('127.0.0.1',server.server_port,context=self.context,timeout=5)
        try:
            client.request(method,path,body=body,headers=headers or {},encode_chunked=chunked)
            response = client.getresponse()
            return response.status,dict(response.getheaders()),response.read()
        finally:
            client.close()

    def admin(self):
        return {'Authorization':'Basic '+base64.b64encode(b'admin:lab-password-for-test-only').decode()}

    def node_request(self, method, path, proto=None, **kw):
        return self.request(self.node,method,path,proto.SerializeToString() if proto is not None else None,
            {'x-api-key':self.base['node_api_key']},**kw)

    def start(self, users=()):
        config = json.dumps(self.app.core_template()['config'])
        result = self.node_request('POST','/start',pb.Backend(config=config,users=users))
        self.assertEqual(result[0],200)
        self.assertTrue(pb.BaseInfoResponse.FromString(result[2]).started)

    def create(self):
        form = urlencode(dict(csrf=self.app.csrf,username='alice',gib='1',days='30')).encode()
        result = self.request(self.ui,'POST','/users/create',form,self.admin())
        self.assertEqual(result[0],303)
        return self.panel_users[42]

    def event(self, kind, cid='0', **env):
        args = cid+',1' if kind in ('CONNECT','REAUTH') else cid
        manager = self.app.vpn.management
        manager.line('>CLIENT:'+kind+','+args)
        for key,value in env.items():
            manager.line('>CLIENT:ENV,'+key+'='+str(value))
        manager.line('>CLIENT:ENV,END')

    def test_authenticated_ui_creates_user_and_downloads_verified_profile(self):
        self.assertEqual(self.request(self.ui,'GET','/')[0],401)
        user = self.create()
        self.assertEqual(user['group_ids'],[7])
        self.assertEqual(user['data_limit'],1024**3)
        self.assertEqual(self.app.state.users()[0]['id'],42)
        code,headers,data = self.request(self.ui,'GET','/profiles/42.ovpn',headers=self.admin())
        self.assertEqual(code,200)
        self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertIn(b'remote-cert-tls server',data)
        self.assertIn(b'verify-x509-name openvpnpa-server name',data)
        self.assertIn(b'<key>',data)
        subprocess.run(['openssl','verify','-CAfile',str(self.pki.root/'ca.crt'),
            '-purpose','sslclient',str(self.pki.root/'client-42.crt')],check=True,stdout=subprocess.DEVNULL)
        self.assertNotIn('proxy_settings',self.app.state.users()[0])

    def test_profile_and_setup_are_not_public_and_csrf_is_required(self):
        for path in ('/setup','/profiles/42.ovpn'):
            self.assertEqual(self.request(self.ui,'GET',path)[0],401)
        self.assertEqual(self.request(self.ui,'POST','/users/create',b'username=alice',self.admin())[0],403)
        self.assertFalse(self.api_calls)

    def test_unenrolled_or_disabled_user_cannot_download(self):
        self.assertEqual(self.request(self.ui,'GET','/profiles/99.ovpn',headers=self.admin())[0],404)
        user = self.create()
        user['status']='disabled'
        self.assertEqual(self.request(self.ui,'GET','/profiles/42.ovpn',headers=self.admin())[0],403)

    def test_node_auth_and_dedicated_inbound_are_required(self):
        self.assertEqual(self.request(self.node,'GET','/info')[0],401)
        self.assertEqual(self.node_request('POST','/start',pb.Backend(config='{"inbounds":[]}'))[0],400)
        self.assertFalse(self.app.state.started)

    def test_protocol_start_connect_usage_final_disconnect_and_no_replay(self):
        self.create()
        self.start([pb.User(email='42',inbounds=['openvpnpa'])])
        self.event('CONNECT',common_name='42',trusted_ip='192.0.2.2')
        self.assertIn('client-auth-nt 0 1',self.sent)
        self.event('ESTABLISHED')
        self.app.vpn.management.line('>BYTECOUNT_CLI:0,100,200')
        code,_,data = self.node_request('GET','/stats/',pb.StatRequest(type=pb.UsersStat,reset=True))
        self.assertEqual(code,200)
        self.assertEqual(sum(s.value for s in pb.StatResponse.FromString(data).stats),300)
        self.event('DISCONNECT',bytes_received=130,bytes_sent=290)
        data = self.node_request('GET','/stats/',pb.StatRequest(type=pb.UsersStat,reset=True))[2]
        self.assertEqual(sum(s.value for s in pb.StatResponse.FromString(data).stats),120)
        data = self.node_request('GET','/stats/',pb.StatRequest(type=pb.UsersStat,reset=True))[2]
        self.assertFalse(pb.StatResponse.FromString(data).stats)

    def test_revocation_and_shared_panel_quota_kill_existing_client(self):
        user = self.create()
        self.start([pb.User(email='42',inbounds=['openvpnpa'])])
        self.event('CONNECT',common_name='42')
        self.event('ESTABLISHED')
        user['used_traffic']=user['data_limit']  # includes other nodes' usage
        self.app.refresh()
        self.app.enforce()
        self.assertTrue(any(command.startswith('client-kill 0 ') for command in self.sent))
        self.assertFalse(self.app.state.authorized('42'))
        self.node_request('PUT','/user/sync',pb.User(email='42'))
        self.event('REAUTH',common_name='42')
        self.assertTrue(self.sent[-1].startswith('client-deny'))

    def test_expiry_and_stale_api_cache_fail_closed(self):
        user = self.create()
        self.start([pb.User(email='42',inbounds=['openvpnpa'])])
        self.assertTrue(self.app.state.authorized('42'))
        user['expire']=time.time()-1
        self.app.refresh()
        self.assertFalse(self.app.state.authorized('42'))
        user['expire']=time.time()+1000
        self.app.refresh()
        self.app.state.db.execute('UPDATE accounts SET checked=0')
        self.assertFalse(self.app.state.authorized('42'))

    def test_expired_node_lease_requires_new_start(self):
        self.create()
        self.start([pb.User(email='42',inbounds=['openvpnpa'])])
        self.app.state.last_request=time.monotonic()-121
        self.node_request('GET','/info')
        self.assertFalse(self.app.state.started)
        self.assertFalse(self.app.state.authorized('42'))

    def test_chunked_http_partial_sync_preserves_other_users(self):
        self.start([pb.User(email='42',inbounds=['openvpnpa']),pb.User(email='43',inbounds=['openvpnpa'])])
        chunk = pb.UsersChunk(index=0,last=True,users=[pb.User(email='42')]).SerializeToString()
        self.assertLess(len(chunk),128)
        frame = bytes([len(chunk)])+chunk
        code,_,_ = self.request(self.node,'PUT','/users/sync/chunked',iter([frame[:2],frame[2:]]),
            {'x-api-key':self.base['node_api_key']},chunked=True)
        self.assertEqual(code,200)
        self.assertEqual(self.app.state.db.execute('SELECT allowed FROM permissions WHERE uid="43"').fetchone(),(1,))
        self.assertEqual(self.app.state.db.execute('SELECT allowed FROM permissions WHERE uid="42"').fetchone(),(0,))

    def test_wrong_or_truncated_chunks_do_not_mutate_permissions(self):
        self.start([pb.User(email='42',inbounds=['openvpnpa'])])
        bad = pb.UsersChunk(index=1,last=True,users=[pb.User(email='42')]).SerializeToString()
        code,_,_ = self.request(self.node,'PUT','/users/sync/chunked',bytes([len(bad)])+bad,
            {'x-api-key':self.base['node_api_key']})
        self.assertEqual(code,400)
        self.assertEqual(self.app.state.db.execute('SELECT allowed FROM permissions WHERE uid="42"').fetchone(),(1,))

    def test_user_stat_reset_does_not_clear_other_users_or_node_total(self):
        self.start()
        self.app.state.sample('b','c1','42',100,200)
        self.app.state.sample('b','c2','43',10,20)
        def count(kind,name=''):
            data = self.node_request('GET','/stats/',pb.StatRequest(type=kind,name=name,reset=True))[2]
            return sum(stat.value for stat in pb.StatResponse.FromString(data).stats)
        self.assertEqual(count(pb.UserStat,'42'),300)
        self.assertEqual(count(pb.UsersStat),30)
        self.assertEqual(count(pb.Outbounds),330)
        self.assertEqual(count(pb.Outbounds),0)

    def test_restart_retains_unreported_bytes_but_requires_fresh_start(self):
        self.create()
        self.start([pb.User(email='42',inbounds=['openvpnpa'])])
        self.app.state.sample('b','c','42',100,200)
        self.app.state.close()
        self.app.state = State(self.app.root/'state.sqlite','openvpnpa')
        self.app.vpn.state = self.app.state
        self.assertFalse(self.app.state.authorized('42'))
        self.start([pb.User(email='42',inbounds=['openvpnpa'])])
        data = self.node_request('GET','/stats/',pb.StatRequest(type=pb.UsersStat,reset=True))[2]
        self.assertEqual(sum(stat.value for stat in pb.StatResponse.FromString(data).stats),300)

    def test_management_does_not_authorize_unknown_certificate_identity(self):
        self.start()
        self.event('CONNECT',common_name='999')
        self.assertTrue(self.sent[-1].startswith('client-deny'))
        self.assertFalse(self.app.vpn.management.clients)

    def test_management_api_never_writes_consumption(self):
        self.create()
        self.app.refresh()
        self.assertTrue(all(method=='GET' or (method=='POST' and path=='/api/user') for method,path in self.api_calls))

    def test_setup_group_selection_persists_and_updates_user_creation(self):
        form = urlencode(dict(csrf=self.app.csrf,group_ids='9,10,9')).encode()
        self.assertEqual(self.request(self.ui,'POST','/settings/groups',form,self.admin())[0],303)
        self.assertEqual(self.app.state.setting('group_ids'),[9,10])
        self.assertEqual(self.create()['group_ids'],[9,10])

    @unittest.skipUnless(shutil.which('openvpn'),'OpenVPN required; run Docker suite')
    def test_generated_server_configuration_reaches_tun_initialization(self):
        (self.app.root/'pki').symlink_to(self.pki.root,target_is_directory=True)
        vpn = VPN(self.app.config,self.app.state,self.app.root)
        try:
            try:
                vpn.start()
            except RuntimeError:
                # On this unprivileged runner, failure MUST be the TUN boundary,
                # not an invalid option, certificate or management command.
                text = (self.app.root/'run/openvpn.log').read_text()
                self.assertRegex(text,r'Cannot open TUN/TAP|Cannot ioctl TUNSETIFF')
                self.assertNotIn('Options error',text)
            else:
                self.assertTrue(vpn.ready.is_set())
        finally:
            vpn.stop()


class SetupTests(unittest.TestCase):
    def test_installer_preflight_stops_without_tun(self):
        release = Path('/etc/os-release').read_text()
        if 'ID=ubuntu\n' not in release or 'VERSION_ID="24.04"' not in release or Path('/dev/net/tun').exists():
            self.skipTest('Requires Ubuntu 24.04 without TUN; run Docker suite')
        result = subprocess.run(['bash',str(Path(__file__).resolve().parents[1]/'install.sh'),'--check'],
            capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,1)
        self.assertIn('TUN device missing',result.stderr)

    def test_private_config_is_validated_and_never_overwritten(self):
        data = dict(public_host='vpn.example.com',panel_url='https://panel.example.com',
            admin_user='admin',admin_password='test-long-password-123',node_api_key=str(uuid4()),
            inbound_tag='openvpnpa',group_ids=[1])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'config.json'
            write_config(path,data)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual(load(path)['vpn_port'],1194)
            with self.assertRaises(FileExistsError):
                write_config(path,data)
            self.assertEqual(json.loads(path.read_text()),data)

    def test_rejects_injection_and_insecure_panel_endpoint(self):
        base = dict(public_host='vpn.example.com',panel_url='https://panel.example.com',
            admin_user='admin',admin_password='test-long-password-123',node_api_key=str(uuid4()),inbound_tag='openvpnpa')
        with tempfile.TemporaryDirectory() as tmp:
            for update in ({'public_host':'vpn.example.com\nscript-security 2'},
                           {'panel_url':'http://panel.example.com'},
                           {'panel_url':'https://token@panel.example.com'},
                           {'vpn_network':'0.0.0.0/0'},{'node_port':8443}):
                with self.subTest(update=update),self.assertRaises(ValueError):
                    write_config(Path(tmp)/'config.json',dict(base,**update))


if __name__=='__main__':
    unittest.main()
