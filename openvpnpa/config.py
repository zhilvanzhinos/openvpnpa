"""Validated local configuration; credentials never enter URLs or logs."""
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID


def hostname(value):
    try:
        ipaddress.IPv4Address(value)
        return value
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", value):
            raise ValueError("public_host must be an IPv4 address or DNS name")
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in value.split('.')):
            raise ValueError("invalid DNS name")
        return value


def load(path):
    return validate(json.loads(Path(path).read_text()))


def normalize_panel_url(value, *, assume_https=False, allow_http=False):
    if not isinstance(value,str) or not value.strip():
        raise ValueError('Adres panel ra vared konid; mesal: https://panel.example.com:8000')
    value = value.strip()
    if assume_https and '://' not in value:
        value = 'https://'+value.removeprefix('//')
    if any(character.isspace() or ord(character)<32 for character in value):
        raise ValueError('Adres panel nabayad fasele ya karakter control dashte bashad.')
    try:
        url = urlsplit(value)
        port = url.port
        valid_host = bool(url.hostname)
        if valid_host:
            try:
                ipaddress.ip_address(url.hostname)
            except ValueError:
                hostname(url.hostname)
    except (ValueError,TypeError):
        raise ValueError('Host ya port panel motabar nist; mesal: https://panel.example.com:8000') from None
    if url.scheme not in (('https','http') if allow_http else ('https',)) or not valid_host:
        raise ValueError('Adres panel bayad HTTPS bashad; HTTP faghat ba entekhab sarihe shoma mojaz ast.')
    if '@' in url.netloc or url.query or url.fragment:
        raise ValueError('Username/password, query ya # ra dar adres panel vared nakonid.')
    if url.netloc.endswith(':') or (port is not None and not 1<=port<=65535):
        raise ValueError('Port panel bayad beyn 1 ta 65535 bashad.')
    return url.geturl().rstrip('/')


def validate(data):
    hostname(data["public_host"])
    data.setdefault('allow_panel_http',False)
    if type(data['allow_panel_http']) is not bool:
        raise ValueError('allow_panel_http must be a boolean')
    data['panel_url'] = normalize_panel_url(data['panel_url'],allow_http=data['allow_panel_http'])
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", data["inbound_tag"]):
        raise ValueError("invalid inbound_tag")
    if not data.get("admin_user") or ':' in data["admin_user"]:
        raise ValueError("invalid admin_user")
    if len(data.get("admin_password", "")) < 16:
        raise ValueError("admin_password must contain at least 16 characters")
    if UUID(data["node_api_key"]).int == 0:
        raise ValueError("node API key cannot be zero")
    for key, default in (("vpn_port",1194), ("ui_port",8443), ("node_port",62050)):
        data.setdefault(key, default)
        if type(data[key]) is not int or not 1 <= data[key] <= 65535:
            raise ValueError("invalid port")
    if data["ui_port"] == data["node_port"]:
        raise ValueError("UI and node TCP ports must differ")
    data.setdefault("group_ids", [])
    data.setdefault("public_ui", False)
    if type(data['public_ui']) is not bool:
        raise ValueError('public_ui must be a boolean')
    if not isinstance(data["group_ids"], list) or any(type(i) is not int or i < 1 for i in data["group_ids"]):
        raise ValueError("group_ids must be positive integers")
    data.setdefault("lease_seconds", 120)
    if type(data["lease_seconds"]) is not int or not 10 <= data["lease_seconds"] <= 300:
        raise ValueError("lease_seconds must be 10..300")
    data.setdefault("vpn_network", "10.89.0.0/24")
    net = ipaddress.IPv4Network(data["vpn_network"])
    if net.prefixlen != 24 or not any(net.subnet_of(ipaddress.IPv4Network(block)) for block in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
        raise ValueError("vpn_network must be a private IPv4 /24")
    return data
