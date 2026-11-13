import json
import ssl
from urllib.request import HTTPSHandler, ProxyHandler, build_opener


def main():
    context = ssl.create_default_context(cafile='/var/lib/openvpnpa/pki/ca.crt')
    client = build_opener(ProxyHandler({}),HTTPSHandler(context=context))
    with client.open('https://127.0.0.1:8443/health',timeout=3) as response:
        if not json.load(response).get('ok'):
            raise SystemExit(1)


if __name__=='__main__':
    main()
