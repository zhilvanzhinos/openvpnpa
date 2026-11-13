"""Interactive setup writes a private JSON file, never shell-evaluated secrets."""
import argparse
import getpass
import json
import os
import secrets
import tempfile
from pathlib import Path
from uuid import uuid4

from .config import load


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
    args = parser.parse_args()
    os.umask(0o077)
    target = Path(args.output)
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
            data = {
                'public_host':ask('Node public IPv4 address or DNS name'),
                'panel_url':ask('PasarGuard HTTPS base URL (no /api suffix)'),
                'panel_token':getpass.getpass('PasarGuard API bearer token (hidden): ',stream=tty),
                'admin_user':ask('Local management username','admin'),
                'admin_password':getpass.getpass('Local management password, at least 16 characters (hidden): ',stream=tty),
                'inbound_tag':ask('Dedicated inbound tag','openvpnpa'),
                'group_ids':[int(v) for v in ask('Dedicated group IDs, comma-separated; blank to configure later','').split(',') if v.strip()],
                'vpn_port':int(ask('Public UDP VPN port',1194)),
                'node_port':int(ask('Public TCP node port',62050)),
                'ui_port':int(ask('Local management HTTPS port',8443)),
            }
    data.setdefault('node_api_key',str(uuid4()))
    data.setdefault('lease_seconds',120)
    data.setdefault('vpn_network','10.89.0.0/24')
    write_config(target,data)
    print('Configuration saved with mode 0600. No credentials were printed.')


if __name__=='__main__':
    main()
