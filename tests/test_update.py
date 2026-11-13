import json
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from openvpnpa.update import Updater, UpdateError, atomic_write


class FakeDocker:
    def __init__(self, root, source):
        self.root,self.source = root,source
        self.calls = []
        self.fail_build = self.fail_start = self.fail_rollback = False
        self.new_traffic = False
        self.sha = 'a'*40
        self.image = 'sha256:'+'b'*64
        self.current = 'openvpnpa-runtime:0.2.0'
        self.health = 'healthy'
        self.files = [root/'releases/old/deploy/compose.yaml']

    def __call__(self, args, *, capture=False, env=None):
        args = [str(a) for a in args]
        self.calls.append(args)
        if args[0]=='git':
            return self.sha+'\n' if 'rev-parse' in args else ''
        if args[:3]==['docker','ps','-aq']:
            return 'old-container\n'
        if args[:2]==['docker','inspect']:
            fmt = args[3]
            if 'Labels' in fmt:
                return json.dumps({'com.docker.compose.project.config_files':','.join(str(p) for p in self.files)})
            if 'Mounts' in fmt:
                return json.dumps([{'Destination':dest,'Source':str(self.root/name)}
                    for dest,name in [('/config','config'),('/var/lib/openvpnpa','state')]])
            if fmt=='{{.Image}}':
                return self.image+'\n'
            if fmt=='{{.Config.Image}}':
                return self.current+'\n'
            return self.health+'\n'
        if 'build' in args and self.fail_build:
            raise subprocess.CalledProcessError(1,args)
        if 'up' in args:
            rollback = any('rollback-image.json' in arg for arg in args)
            if not rollback and self.new_traffic:
                (self.root/'state/traffic').write_text('307')
            if (rollback and self.fail_rollback) or (not rollback and self.fail_start):
                raise subprocess.CalledProcessError(1,args)
        return ''


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.root,self.source = base/'installed',base/'source'
        for path in (self.root/'config',self.root/'state',self.root/'releases/old/deploy',self.source/'deploy'):
            path.mkdir(parents=True,exist_ok=True)
        (self.root/'config/config.json').write_text('{"private":"fixture-password"}')
        (self.root/'config/compose.env').write_text('UI_BIND=127.0.0.1\nVPN_PORT=1194\n')
        (self.root/'state/traffic').write_text('300')
        (self.root/'state/ca.key').write_text('fixture-private-key')
        (self.root/'releases/old/deploy/compose.yaml').write_text('services: {}\n')
        (self.source/'deploy/compose.yaml').write_text('services: {}\n')
        (self.source/'update.sh').write_text('#!/usr/bin/env bash\nset -euo pipefail\numask 077\n# Managed by OpenVPNPA updater\n')
        self.fake = FakeDocker(self.root,self.source)
        self.messages = []
        self.updater = Updater(self.root,self.source,self.fake,self.messages.append)

    def tearDown(self):
        self.tmp.cleanup()

    def test_success_builds_before_stop_and_preserves_all_application_data(self):
        before = {str(p.relative_to(self.root)):p.read_bytes() for name in ('config','state') for p in (self.root/name).iterdir()}
        self.updater.execute()
        after = {str(p.relative_to(self.root)):p.read_bytes() for name in ('config','state') for p in (self.root/name).iterdir()}
        self.assertEqual(before,after)
        build = next(i for i,c in enumerate(self.fake.calls) if 'build' in c)
        stop = next(i for i,c in enumerate(self.fake.calls) if 'stop' in c)
        up = next(i for i,c in enumerate(self.fake.calls) if 'up' in c)
        self.assertLess(build,stop)
        self.assertLess(stop,up)
        self.assertTrue((self.root/'update').exists())
        self.assertEqual((self.root/'update').stat().st_mode & 0o777,0o700)
        metadata = json.loads((self.root/'last-update.json').read_text())
        self.assertEqual(metadata['commit'],self.fake.sha)
        archive = Path(metadata['backup'])/'config-state.tar.gz'
        self.assertEqual(archive.stat().st_mode & 0o777,0o600)
        with tarfile.open(archive) as backup:
            self.assertEqual(backup.extractfile('state/traffic').read(),b'300')
            self.assertEqual(backup.extractfile('state/ca.key').read(),b'fixture-private-key')
        self.assertNotIn('fixture-password','\n'.join(self.messages))

    def test_build_failure_never_stops_the_running_service(self):
        self.fake.fail_build = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.updater.execute()
        self.assertFalse(any('stop' in c or 'up' in c for c in self.fake.calls))
        self.assertFalse((self.root/'backups').exists())
        self.assertEqual((self.root/'state/traffic').read_text(),'300')

    def test_failed_health_rolls_back_image_without_restoring_over_new_traffic(self):
        self.fake.fail_start = True
        self.fake.new_traffic = True
        with self.assertRaisesRegex(UpdateError,'image ghabli bargasht'):
            self.updater.execute()
        starts = [c for c in self.fake.calls if 'up' in c]
        self.assertEqual(len(starts),2)
        self.assertTrue(any('rollback-image.json' in p for p in starts[1]))
        self.assertEqual((self.root/'state/traffic').read_text(),'307')
        self.assertFalse((self.root/'last-update.json').exists())

    def test_rollback_failure_reports_backup_without_destroying_state(self):
        self.fake.fail_start = self.fake.fail_rollback = True
        with self.assertRaisesRegex(UpdateError,'Rollback ham namovafagh'):
            self.updater.execute()
        self.assertEqual((self.root/'state/traffic').read_text(),'300')
        self.assertEqual(len(list((self.root/'backups').glob('*/config-state.tar.gz'))),1)

    def test_same_healthy_commit_is_a_noop(self):
        self.fake.current = 'openvpnpa-runtime:git-'+self.fake.sha
        self.updater.execute()
        self.assertFalse(any('build' in c or 'stop' in c or 'up' in c for c in self.fake.calls))
        self.assertFalse((self.root/'releases'/('git-'+self.fake.sha)).exists())

    def test_custom_compose_override_is_preserved_and_blocks_automatic_replacement(self):
        custom = self.root/'custom.yaml'
        custom.write_text('services: {node: {network_mode: host}}\n')
        self.fake.files.append(custom)
        with self.assertRaisesRegex(UpdateError,'override ekhtesasi'):
            self.updater.execute()
        self.assertFalse(any('build' in c or 'stop' in c for c in self.fake.calls))
        self.assertTrue(custom.exists())

    def test_custom_helpers_are_not_overwritten(self):
        (self.root/'manage').write_text('# custom manage\n')
        (self.root/'update').write_text('# custom update\n')
        self.updater.execute()
        self.assertEqual((self.root/'manage').read_text(),'# custom manage\n')
        self.assertEqual((self.root/'update').read_text(),'# custom update\n')
        self.assertTrue((self.root/'manage-updated').exists())
        self.assertTrue((self.root/'update-from-github').exists())

    def test_metadata_write_failure_restores_previous_helpers_and_keeps_new_traffic(self):
        old_manage = '#!/usr/bin/env bash\nset -euo pipefail\nROOT=/opt/openvpnpa\nexec docker compose --project-name openvpnpa --env-file "$ROOT/config/compose.env" -f "$ROOT/releases/v0.2.0-beta.5/deploy/compose.yaml" "$@"\n'
        old_update = '#!/usr/bin/env bash\nset -euo pipefail\numask 077\n# Managed by OpenVPNPA updater\necho old\n'
        (self.root/'manage').write_text(old_manage)
        (self.root/'update').write_text(old_update)
        (self.root/'manage').chmod(0o700)
        (self.root/'update').chmod(0o700)
        self.fake.new_traffic = True
        def fail_metadata(path, text, mode=0o600):
            if path.name=='last-update.json':
                raise OSError('simulated metadata write failure')
            atomic_write(path,text,mode)
        with patch('openvpnpa.update.atomic_write',side_effect=fail_metadata):
            with self.assertRaisesRegex(UpdateError,'image ghabli bargasht'):
                self.updater.execute()
        self.assertEqual((self.root/'manage').read_text(),old_manage)
        self.assertEqual((self.root/'update').read_text(),old_update)
        self.assertEqual((self.root/'manage').stat().st_mode & 0o777,0o700)
        self.assertEqual((self.root/'state/traffic').read_text(),'307')


if __name__=='__main__':
    unittest.main()
