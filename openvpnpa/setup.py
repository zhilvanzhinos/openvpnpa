"""Interactive setup writes a private JSON file, never shell-evaluated secrets."""
import argparse
import getpass
import json
import os
import secrets
import tempfile
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from .config import load, validate, hostname, normalize_panel_url
from .panel import Panel, PanelError


@contextmanager
def terminal():
    # Buffered r+ requires seekability, which terminals do not provide. Keep
    # independent read/write streams so curl | sudo bash remains interactive.
    with open('/dev/tty','r') as reader, open('/dev/tty','w',buffering=1) as writer:
        yield reader,writer


def collect(ask, secret):
    """The entire questionnaire lives on /dev/tty, including when curl is piped."""
    node_key = str(uuid4())
    def port(prompt, default):
        while True:
            try:
                value = int(ask(prompt,default))
                if 1<=value<=65535:
                    return value
            except ValueError:
                pass
            print('Port bayad adadi beyn 1 ta 65535 bashad.')
    while True:
        host = ask('IP omumi IPv4 ya domain hamin server')
        try:
            hostname(host)
            break
        except (ValueError,TypeError):
            print('Adres motabar vared konid; bedoon https va bedoon port.')
    while True:
        value = ask('Adres panel PasarGuard; mesal https://panel.example.com:8000 (bedoon /api)')
        allow_http = False
        if isinstance(value,str) and value.strip().lower().startswith('http://'):
            print('HTTP ramz va token ra bedoon TLS mifrestad; faghat dar network motmaen estefade konid.')
            if str(ask('Ba hamin adres HTTP edame bedahim? y/n','n')).lower() not in ('y','yes','bale'):
                continue
            allow_http = True
        try:
            panel_url = normalize_panel_url(value,assume_https=True,allow_http=allow_http)
            break
        except ValueError as error:
            print(str(error))
    admin_user = ask('Username admin panel OpenVPN','admin')
    while True:
        password = secret('Password panel OpenVPN, hadeaghal 16 karakter: ')
        if len(password)>=16 and password==secret('Tekrar password panel OpenVPN: '):
            break
        print('Password bayad hadeaghal 16 karakter bashad va tekrar an yeksan bashad.')
    public_ui = str(ask('Panel OpenVPN az biron server ghabel dastresi bashad? y/n','y')).lower() in ('y','yes','bale')
    tag = ask('Tag ekhtesasi in node','openvpnpa_'+node_key.replace('-','')[:8])
    groups = ask('ID group ekhtesasi dar PasarGuard; agar nadarid Enter bezanid','')
    data = validate(dict(public_host=host,panel_url=panel_url,allow_panel_http=allow_http,admin_user=admin_user,
        admin_password=password,public_ui=public_ui,inbound_tag=tag,
        group_ids=[int(value.strip()) for value in groups.split(',') if value.strip()],
        node_api_key=node_key,vpn_port=port('Port UDP etesal OpenVPN',1194),
        node_port=port('Port TCP etesal node be PasarGuard',62050),
        ui_port=port('Port HTTPS panel OpenVPN',8443)))
    while True:
        method = str(ask('Vorood be PasarGuard: 1 username/password, 2 API token','1'))
        if method in ('1','2'):
            break
        print('Adad 1 ya 2 ra vared konid.')
    panel = Panel(data)
    if method=='1':
        username = ask('Username admin PasarGuard')
        data['panel_token'] = panel.login(username,secret('Password admin PasarGuard (zakhire nemishavad): '))
    else:
        data['panel_token'] = secret('API token PasarGuard: ')
        panel.request('GET','/api/users?limit=1')
    return data


def summary(config_path, state_path):
    data = load(config_path)
    certificate = (Path(state_path)/'pki/ca.crt').read_text().strip()
    if not certificate.startswith('-----BEGIN CERTIFICATE-----') or not certificate.endswith('-----END CERTIFICATE-----') or 'PRIVATE KEY' in certificate:
        raise ValueError('invalid public CA certificate; refusing to display private material')
    env = Path(config_path).parent/'compose.env'
    public = data['public_ui']
    if env.exists():
        rows = dict(line.split('=',1) for line in env.read_text().splitlines() if '=' in line and not line.startswith('#'))
        public = rows.get('UI_BIND','127.0.0.1')!='127.0.0.1'
    print('\n'+'='*64)
    print('Nasb panel va node OpenVPN anjam shod')
    print('Adres panel: https://'+(data['public_host'] if public else 'localhost')+':'+str(data['ui_port']))
    print('Username admin panel: '+data['admin_user'])
    if not public:
        print('Panel faghat rooye loopback ast; az SSH forwarding estefade konid.')
    print('\nMoshakhasat baraye ezafe kardan node jadid dar PasarGuard:')
    print('Connection type: REST')
    print('Address: '+data['public_host'])
    print('Port: '+str(data['node_port']))
    print('API Port: '+str(data['node_port']))
    print('Inbound tag: '+data['inbound_tag'])
    print('Usage coefficient: 1')
    print('Keep alive: 60')
    print('\nAPI Key:\n'+data['node_api_key'])
    print('\nCertificate (server_ca):\n'+certificate)
    print('='*64)
    print('In Certificate omumi ast; private key CA namayesh dade nemishavad.')
    print('Bad az sabt node va group ekhtesasi, ID group ra dar safhe /setup panel OpenVPN zakhire konid.')


def write_config(target, data):
    target = Path(target)
    target.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    if target.exists():
        raise FileExistsError('Existing configuration is preserved; edit it explicitly')
    descriptor,path = tempfile.mkstemp(prefix='.config-',dir=target.parent)
    try:
        with os.fdopen(descriptor,'w') as stream:
            os.fchmod(stream.fileno(),0o600)
            json.dump(data,stream,indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        load(path)
        # Hard-link provides no-overwrite creation, including competing setup.
        os.link(path,target)
    finally:
        os.unlink(path)


def main():
    parser = argparse.ArgumentParser(description='Configure OpenVPNPA without putting secrets in command arguments')
    parser.add_argument('--output',required=True)
    parser.add_argument('--from-file',help='Private JSON input for unattended installation')
    parser.add_argument('--summary',action='store_true',help='Display node API key and complete public CA certificate')
    parser.add_argument('--state',default='/opt/openvpnpa/state')
    args = parser.parse_args()
    os.umask(0o077)
    target = Path(args.output)
    if args.summary:
        summary(target,args.state)
        return
    if target.exists():
        load(target)
        print('Existing configuration validated and preserved')
        return
    if args.from_file:
        data = json.loads(Path(args.from_file).read_text())
    else:
        with terminal() as (reader,writer):
            def ask(prompt, default=None):
                writer.write(prompt+(' ['+str(default)+']' if default is not None else '')+': ')
                writer.flush()
                value = reader.readline()
                if not value:
                    raise ValueError('Interactive terminal closed')
                return value.strip() or default
            data = collect(ask,lambda prompt:getpass.getpass(prompt,stream=writer))
    data.setdefault('node_api_key',str(uuid4()))
    data.setdefault('lease_seconds',120)
    data.setdefault('vpn_network','10.89.0.0/24')
    write_config(target,data)
    print('Configuration saved with mode 0600. No credentials were printed.')


if __name__=='__main__':
    try:
        main()
    except (ValueError,PanelError) as error:
        raise SystemExit('Tanzimat kamel nashod: '+str(error)) from None
