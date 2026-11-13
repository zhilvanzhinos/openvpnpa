"""Interactive setup writes a private JSON file, never shell-evaluated secrets."""
import argparse
import getpass
import json
import os
import secrets
import tempfile
from pathlib import Path
from uuid import uuid4

from .config import load, validate, hostname
from .panel import Panel, PanelError


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
            print('پورت باید عددی بین ۱ و ۶۵۵۳۵ باشد.')
    while True:
        host = ask('IP عمومی IPv4 یا دامنه همین سرور')
        try:
            hostname(host)
            break
        except (ValueError,TypeError):
            print('آدرس معتبر وارد کنید؛ بدون https و بدون پورت.')
    panel_url = ask('آدرس HTTPS پنل پاسارگارد، بدون /api انتهایی')
    admin_user = ask('نام مدیر پنل OpenVPN','admin')
    while True:
        password = secret('رمز پنل OpenVPN، حداقل ۱۶ کاراکتر: ')
        if len(password)>=16 and password==secret('تکرار رمز پنل OpenVPN: '):
            break
        print('رمز باید حداقل ۱۶ کاراکتر باشد و تکرار آن مطابقت داشته باشد.')
    public_ui = str(ask('پنل OpenVPN از بیرون سرور قابل دسترسی باشد؟ y/n','y')).lower() in ('y','yes','بله')
    tag = ask('تگ اختصاصی این نود','openvpnpa_'+node_key.replace('-','')[:8])
    groups = ask('شناسه گروه اختصاصی در پاسارگارد، اگر دارید؛ وگرنه Enter','')
    data = validate(dict(public_host=host,panel_url=panel_url,admin_user=admin_user,
        admin_password=password,public_ui=public_ui,inbound_tag=tag,
        group_ids=[int(value.strip()) for value in groups.split(',') if value.strip()],
        node_api_key=node_key,vpn_port=port('پورت UDP اتصال OpenVPN',1194),
        node_port=port('پورت TCP ارتباط نود با پاسارگارد',62050),
        ui_port=port('پورت HTTPS پنل OpenVPN',8443)))
    while True:
        method = str(ask('ورود به پاسارگارد: 1 نام کاربری/رمز، 2 توکن API','1'))
        if method in ('1','2'):
            break
        print('عدد ۱ یا ۲ را وارد کنید.')
    panel = Panel(data)
    if method=='1':
        username = ask('نام کاربری مدیر پاسارگارد')
        data['panel_token'] = panel.login(username,secret('رمز مدیر پاسارگارد (ذخیره نمی‌شود): '))
    else:
        data['panel_token'] = secret('توکن API پاسارگارد: ')
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
    print('نصب پنل و نود OpenVPN انجام شد')
    print('آدرس پنل: https://'+(data['public_host'] if public else 'localhost')+':'+str(data['ui_port']))
    print('نام مدیر پنل: '+data['admin_user'])
    if not public:
        print('پنل فقط روی loopback است؛ برای دسترسی از SSH forwarding استفاده کنید.')
    print('\nمشخصات برای افزودن نود جدید در پاسارگارد:')
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
    print('این Certificate عمومی است؛ کلید خصوصی CA هرگز نمایش داده نمی‌شود.')
    print('پس از ثبت نود و گروه اختصاصی، شناسه گروه را در صفحه /setup پنل OpenVPN ذخیره کنید.')


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
        with open('/dev/tty','r+') as tty:
            def ask(prompt, default=None):
                tty.write(prompt+(' ['+str(default)+']' if default is not None else '')+': ')
                tty.flush()
                value = tty.readline()
                if not value:
                    raise ValueError('Interactive terminal closed')
                return value.strip() or default
            data = collect(ask,lambda prompt:getpass.getpass(prompt,stream=tty))
    data.setdefault('node_api_key',str(uuid4()))
    data.setdefault('lease_seconds',120)
    data.setdefault('vpn_network','10.89.0.0/24')
    write_config(target,data)
    print('Configuration saved with mode 0600. No credentials were printed.')


if __name__=='__main__':
    try:
        main()
    except (ValueError,PanelError) as error:
        raise SystemExit('تنظیمات کامل نشد: '+str(error)) from None
