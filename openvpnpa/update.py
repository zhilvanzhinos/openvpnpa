"""Host-side updater. No panel writes, credential output or ledger restoration."""
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class UpdateError(Exception):
    pass


def run(argv, *, capture=False, env=None):
    return subprocess.run([str(arg) for arg in argv],check=True,text=True,
        stdout=subprocess.PIPE if capture else None,env=env).stdout


def atomic_write(path, text, mode=0o600):
    fd,temporary = tempfile.mkstemp(prefix='.update-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),mode)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class Updater:
    def __init__(self, root, source, runner=run, report=print):
        self.root,self.source = Path(root).resolve(),Path(source).resolve()
        self.run,self.report = runner,report
        self.changed_helpers = {}
        self.env = dict(os.environ,OPENVPNPA_CONFIG_DIR=str(self.root/'config'),
            OPENVPNPA_STATE_DIR=str(self.root/'state'))

    def command(self, *args, capture=False):
        return self.run(list(args),capture=capture,env=self.env)

    def compose(self, files):
        args = ['docker','compose','--project-name','openvpnpa','--env-file',str(self.root/'config/compose.env')]
        for file in files:
            args.extend(['-f',str(file)])
        return args

    def image_override(self, path, image):
        text = json.dumps({'services':{'node':{'image':image}}})+'\n'
        if path.is_symlink():
            raise UpdateError('Image override local symlink ast; file hefz shod.')
        if path.exists() and path.read_text()!=text:
            raise UpdateError('Image override local taghir karde ast; file hefz shod.')
        atomic_write(path,text)

    def inspect(self):
        ids = self.command('docker','ps','-aq','--filter','label=com.docker.compose.project=openvpnpa',
            '--filter','label=com.docker.compose.service=node',capture=True).split()
        if len(ids)!=1:
            raise UpdateError('Bayad yek container node az nasb ghabli peyda shavad; hich service taghir nakard.')
        labels = json.loads(self.command('docker','inspect','--format','{{json .Config.Labels}}',ids[0],capture=True))
        files = [Path(item).resolve() for item in labels.get('com.docker.compose.project.config_files','').split(',') if item]
        if not files:
            raise UpdateError('Compose file nasb ghabli peyda nashod.')
        for file in files:
            if not file.is_relative_to(self.root) or not file.is_file():
                raise UpdateError('Masir Compose nasb ghabli kharej az installation ast ya vojood nadarad.')
            if file.name=='compose.yaml' and file.parent.name=='deploy':
                continue
            if file.name=='compose.cloud.yaml' and file.parent.name=='deploy':
                continue
            # Only updater-generated image-only overrides may be transferred.
            try:
                value = json.loads(file.read_text())
                image = value['services']['node']['image']
                if value=={'services':{'node':{'image':image}}} and isinstance(image,str):
                    continue
            except (ValueError,KeyError,TypeError):
                pass
            raise UpdateError('Compose override ekhtesasi peyda shod; baraye hefz an update khodkar motovaghef shod.')
        mounts = json.loads(self.command('docker','inspect','--format','{{json .Mounts}}',ids[0],capture=True))
        for destination,expected in [('/config',self.root/'config'),('/var/lib/openvpnpa',self.root/'state')]:
            matches = [item for item in mounts if item.get('Destination')==destination]
            if len(matches)!=1 or Path(matches[0]['Source']).resolve()!=expected.resolve():
                raise UpdateError('Volume nasb ghabli ba masir standard motabegh nist; hich taghiri anjam nashod.')
        image = self.command('docker','inspect','--format','{{.Image}}',ids[0],capture=True).strip()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}',image):
            raise UpdateError('Image ghabli ghabel tashkhis nist.')
        health = self.command('docker','inspect','--format','{{if .State.Health}}{{.State.Health.Status}}{{end}}',ids[0],capture=True).strip()
        current_image = self.command('docker','inspect','--format','{{.Config.Image}}',ids[0],capture=True).strip()
        return files,image,health,current_image

    def backup(self, folder):
        # Caller has stopped the node gracefully: SQLite WAL and final samples
        # are quiescent. This archive is never auto-restored over live traffic.
        archive = folder/'config-state.tar.gz'
        with tarfile.open(archive,'w:gz',dereference=False) as stream:
            stream.add((self.root/'config').resolve(),arcname='config')
            stream.add((self.root/'state').resolve(),arcname='state')
        archive.chmod(0o600)

    def install_helpers(self, files):
        arguments = ['env','OPENVPNPA_CONFIG_DIR='+str(self.root/'config'),
            'OPENVPNPA_STATE_DIR='+str(self.root/'state')]+self.compose(files)
        text = '#!/usr/bin/env bash\nset -euo pipefail\n# Managed by OpenVPNPA updater\nexec '+shlex.join(arguments)+' "$@"\n'
        manage = self.root/'manage'
        if manage.exists() or manage.is_symlink():
            existing = '' if manage.is_symlink() else manage.read_text()
            known_legacy = re.fullmatch(r'#!/usr/bin/env bash\nset -euo pipefail\nROOT=/opt/openvpnpa\nexec docker compose --project-name openvpnpa --env-file "\$ROOT/config/compose.env" -f "\$ROOT/releases/v[0-9A-Za-z.+-]+/deploy/compose.yaml" "\$@"\n',existing)
            known_updater = existing.startswith('#!/usr/bin/env bash\nset -euo pipefail\n# Managed by OpenVPNPA updater\nexec env OPENVPNPA_CONFIG_DIR=') and ' --project-name openvpnpa ' in existing
            if not known_legacy and not known_updater and existing!=text:
                manage = self.root/'manage-updated'
                if manage.is_symlink() or (manage.exists() and manage.read_text()!=text):
                    raise UpdateError('Manage helper ekhtesasi hefz shod; nam helper jadid ham eshghal ast.')
        self.write_helper(manage,text)
        update = self.root/'update'
        content = (self.source/'update.sh').read_text()
        if update.is_symlink() or (update.exists() and update.read_text()!=content and not update.read_text().startswith('#!/usr/bin/env bash\nset -euo pipefail\numask 077\n# Managed by OpenVPNPA updater\n')):
            update = self.root/'update-from-github'
            if update.is_symlink() or (update.exists() and update.read_text()!=content):
                raise UpdateError('Helper update ekhtesasi hefz shod; nam helper jadid ham eshghal ast.')
        self.write_helper(update,content)
        return manage,update

    def write_helper(self, path, text):
        self.changed_helpers[path] = (path.read_text(),path.stat().st_mode & 0o777) if path.exists() else None
        atomic_write(path,text,0o700)

    def restore_helpers(self):
        for path,previous in self.changed_helpers.items():
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path,*previous)

    def execute(self):
        for path in ('config/config.json','config/compose.env','state'):
            if not (self.root/path).exists():
                raise UpdateError('Nasb ghabli kamel nist; config/state vojood nadarad.')
        sha = self.command('git','-C',self.source,'rev-parse','--verify','HEAD^{commit}',capture=True).strip()
        if not re.fullmatch(r'[0-9a-f]{40}',sha):
            raise UpdateError('Commit Git motabar nist.')
        previous,image,health,current_image = self.inspect()
        image_tag = 'openvpnpa-runtime:git-'+sha
        if current_image==image_tag and health=='healthy':
            self.report('Akharin version nasb ast; restart lazem nist. Commit: '+sha[:12])
            return
        releases = self.root/'releases'
        releases.mkdir(mode=0o700,exist_ok=True)
        release = releases/('git-'+sha)
        if release.exists():
            self.command('git','-C',release,'diff','--quiet')
            self.command('git','-C',release,'diff','--cached','--quiet')
            if self.command('git','-C',release,'rev-parse','HEAD',capture=True).strip()!=sha:
                raise UpdateError('Checkout local ba commit darkhasti motabegh nist.')
        else:
            shutil.copytree(self.source,release,symlinks=True)
        override = release/'.openvpnpa-image.json'
        self.image_override(override,image_tag)
        files = [release/'deploy/compose.yaml',override]
        build_files = list(files)
        if os.environ.get('CODEX_PROXY_CERT'):
            self.env['OPENVPNPA_CA_BUNDLE']='/etc/ssl/certs/ca-certificates.crt'
            build_files.append(release/'deploy/compose.cloud.yaml')
        self.command(*self.compose(files),'config','--quiet')
        self.report('Build version jadid; service ghabli hanooz dar hale ejra ast...')
        self.command(*self.compose(build_files),'build','node')
        backups = self.root/'backups'
        backups.mkdir(mode=0o700,exist_ok=True)
        folder = backups/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid4().hex[:8])
        folder.mkdir(mode=0o700)
        rollback_image = 'openvpnpa-runtime:rollback-'+folder.name.lower()
        self.command('docker','image','tag',image,rollback_image)
        rollback_override = folder/'rollback-image.json'
        self.image_override(rollback_override,rollback_image)
        rollback = self.compose(previous+[rollback_override])
        stopped = False
        try:
            self.report('Restart kotah: sabt masraf nahayi va backup config/state...')
            stopped = True
            self.command(*self.compose(previous),'stop','-t','30','node')
            self.backup(folder)
            self.command(*self.compose(files),'up','-d','--no-build','--pull','never','--force-recreate','--wait','--wait-timeout','90','node')
            manage,update = self.install_helpers(files)
            atomic_write(self.root/'last-update.json',json.dumps({'commit':sha,'compose_files':[str(p) for p in files],
                'backup':str(folder),'previous_image':image},indent=2)+'\n')
        except Exception as error:
            if stopped:
                self.report('Update namovafagh bood; bazgasht be image ghabli...')
                try:
                    self.restore_helpers()
                    self.command(*rollback,'up','-d','--no-build','--pull','never','--force-recreate','--wait','--wait-timeout','90','node')
                except Exception:
                    raise UpdateError('Rollback ham namovafagh bood. Backup: '+str(folder)+'. State khodkar restore nashod ta masraf pak nashavad.') from error
            raise UpdateError('Update namovafagh bood; image ghabli bargasht. Backup: '+str(folder)) from error
        self.report('Update movafagh bood. Commit: '+sha[:12])
        self.report('Config, API Key, Certificate va masraf hefz shod. Backup: '+str(folder))
        self.report('Update bad: sudo '+str(update))
        self.report('Log: sudo '+str(manage)+' logs --tail=100 node')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root',default='/opt/openvpnpa')
    parser.add_argument('--source',required=True)
    args = parser.parse_args()
    if os.geteuid()!=0:
        raise SystemExit('Ba sudo ejra konid.')
    os.umask(0o077)
    try:
        Updater(args.root,args.source).execute()
    except (UpdateError,subprocess.CalledProcessError,OSError) as error:
        raise SystemExit('Update kamel nashod: '+str(error)) from None


if __name__=='__main__':
    main()
