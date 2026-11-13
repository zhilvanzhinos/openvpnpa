"""Run the official SDK in another interpreter against our real TLS adapter.

Usage: python -m scripts.check_bridge --bridge-python /path/to/sdk-venv/bin/python
The second interpreter avoids conflicting protobuf service descriptors. No
active panel, VPN device or external network is contacted during this check.
"""
import argparse
import json
import secrets
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from openvpnpa.app import App
from openvpnpa.server import NodeHandler, serve


CLIENT = '''
import asyncio,json,sys
from PasarGuardNodeBridge.rest import Node
from PasarGuardNodeBridge.common import service_pb2 as pb

async def main():
    cfg=json.load(open(sys.argv[1]))
    async with Node(address="127.0.0.1",port=cfg["port"],api_port=cfg["port"],
        server_ca=cfg["ca"],api_key=cfg["key"]) as node:
        info=await node.info()
        assert not info.started
        result=await node.start(config=json.dumps(cfg["core"]),backend_type=pb.XRAY,
            users=[pb.User(email="42",inbounds=["openvpnpa"])],keep_alive=60)
        assert result.started
        assert (await node.get_backend_stats()).uptime>=0
        assert (await node.get_system_stats()).cpu_cores>=1
        result=await node.get_stats(stat_type=pb.UsersStat,reset=True)
        assert sum(stat.value for stat in result.stats)==300
        assert not (await node.get_stats(stat_type=pb.UsersStat,reset=True)).stats
        await node.sync_users_chunked([pb.User(email="42")],chunk_size=1)
        await node.sync_users([pb.User(email="43",inbounds=["openvpnpa"])])
    print("Official SDK: TLS, Start, stats/reset, chunked partial sync, full sync and Stop passed")
asyncio.run(main())
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bridge-python',required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        config = dict(public_host='127.0.0.1',panel_url='https://unused.invalid',panel_token='',
            admin_user='admin',admin_password=secrets.token_urlsafe(24),node_api_key=str(uuid4()),
            inbound_tag='openvpnpa',group_ids=[],lease_seconds=120,vpn_network='10.89.0.0/24')
        app = App(config,tmp)
        app.pki.initialize()
        app.vpn.ready.set()
        app.state.sample('boot','session','42',100,200)
        server,thread = serve(app,('127.0.0.1',0),NodeHandler)
        cfg = Path(tmp)/'sdk.json'
        cfg.write_text(json.dumps(dict(port=server.server_port,key=config['node_api_key'],
            ca=(app.pki.root/'ca.crt').read_text(),core=app.core_template()['config'])))
        cfg.chmod(0o600)
        try:
            subprocess.run([args.bridge_python,'-c',CLIENT,str(cfg)],check=True,timeout=40)
            row = app.state.db.execute('SELECT uid,allowed FROM permissions').fetchall()
            assert row==[('43',1)], row
            assert not app.state.started
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            app.state.close()


if __name__=='__main__':
    main()
