"""PasarGuard 5.5.1 offset/limit listing contract and failure boundaries."""
import unittest
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from openvpnpa.panel import Panel, PanelError


class PaginationTests(unittest.TestCase):
    def panel(self, pages):
        panel = Panel({'panel_url':'https://panel.example'})
        panel.request = Mock(side_effect=pages)
        return panel

    def test_server_page_cap_and_duplicate_uid_at_page_boundary(self):
        panel = self.panel([
            dict(users=[{'id':1},{'id':2}],total=5),
            dict(users=[{'id':2},{'id':3}],total=5),
            dict(users=[{'id':4}],total=5)])
        self.assertEqual([u['id'] for u in panel.users()],[1,2,2,3,4])
        queries = [parse_qs(urlsplit(call.args[1]).query) for call in panel.request.call_args_list]
        self.assertEqual([q['offset'] for q in queries],[['0'],['2'],['4']])
        self.assertTrue(all(q['sort']==['username'] for q in queries))

    def test_empty_panel(self):
        self.assertEqual(list(self.panel([dict(users=[],total=0)]).users()),[])

    def test_malformed_incomplete_and_nonprogressing_pages_fail(self):
        for pages in ([{}], [dict(users=[],total=1)],
                      [dict(users=[{'id':0}],total=1)],
                      [dict(users=[{'id':1}],total='1')],
                      [dict(users=[{'id':1}],total=3),dict(users=[{'id':1}],total=3)]):
            with self.subTest(pages=pages), self.assertRaises(PanelError):
                list(self.panel(pages).users())

    def test_mid_import_network_failure_propagates(self):
        panel = self.panel([dict(users=[{'id':1}],total=2),PanelError('unavailable')])
        stream = panel.users()
        self.assertEqual(next(stream),{'id':1})
        with self.assertRaises(PanelError):
            next(stream)
