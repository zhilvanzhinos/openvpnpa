"""Exercise a real Docker replacement and rollback in an isolated dummy project.

No VPN, real panel, published ports, or existing OpenVPNPA service is used.
"""
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from openvpnpa.update import Updater, UpdateError, run


def main():
    name = 'openvpnpa-updatecheck-'+uuid4().hex[:10]
    old_tag = 'openvpnpa-updatecheck:'+name
    tags = {old_tag}
    last_files = []
    with tempfile.TemporaryDirectory(prefix='openvpnpa-updatecheck-') as directory:
        base = Path(directory)
        root,source = base/'installed',base/'source'
        for path in (root/'config',root/'state',source/'deploy'):
            path.mkdir(parents=True,exist_ok=True)
        (root/'config/config.json').write_text('{"fixture":"not-a-real-secret"}')
        (root/'config/compose.env').write_text('UI_BIND=127.0.0.1\n')
        (root/'state/traffic').write_text('300')
        (root/'state/ca.key').write_text('fixture-ca-key')
        # These are synthetic, non-secret files. Allow the rootless Docker UID
        # mapping to read them; production configuration permissions are never
        # changed by this script or the updater.
        (root/'state').chmod(0o755)
        (root/'state/traffic').chmod(0o644)
        compose = {'services':{'node':{'image':old_tag,'build':{'context':'..','dockerfile':'deploy/Dockerfile'},
            'command':['sleep','infinity'],'read_only':True,'cap_drop':['ALL'],
            'volumes':[str(root/'config')+':/config:ro',str(root/'state')+':/var/lib/openvpnpa'],
            'healthcheck':{'test':['CMD','true'],'interval':'1s','timeout':'1s','retries':1}}}}
        (source/'deploy/compose.yaml').write_text(json.dumps(compose))
        (source/'deploy/compose.cloud.yaml').write_text('{"services":{"node":{}}}\n')
        (source/'deploy/Dockerfile').write_text('FROM ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5\nCMD ["sleep", "infinity"]\n')
        shutil.copyfile(Path(__file__).resolve().parents[1]/'update.sh',source/'update.sh')
        old = root/'releases/old'
        shutil.copytree(source,old)
        with (source/'deploy/Dockerfile').open('a') as stream:
            stream.write('LABEL openvpnpa.test.revision="first"\n')
        run(['git','init','-q',str(source)])
        def commit():
            run(['git','-C',str(source),'add','.'])
            run(['git','-C',str(source),'-c','user.name=OpenVPNPA Test','-c','user.email=test@example.invalid',
                'commit','-qm','fixture'])
            sha = run(['git','-C',str(source),'rev-parse','HEAD'],capture=True).strip()
            tags.add('openvpnpa-runtime:git-'+sha)
            return sha
        first = commit()

        def isolated(args, *, capture=False, env=None):
            nonlocal last_files
            args = [str(a) for a in args]
            # Only the Compose project name is substituted. Real images,
            # volumes, health checks and rollback operations are exercised.
            args = [name if arg=='openvpnpa' else arg.replace(
                'label=com.docker.compose.project=openvpnpa',
                'label=com.docker.compose.project='+name) for arg in args]
            if '--wait-timeout' in args:
                args[args.index('--wait-timeout')+1]='5'
            if args[:3]==['docker','image','tag']:
                tags.add(args[-1])
            if args[:2]==['docker','compose']:
                last_files = [args[index+1] for index,arg in enumerate(args) if arg=='-f']
            return run(args,capture=capture,env=env)

        def digest():
            return {str(path.relative_to(root)):hashlib.sha256(path.read_bytes()).hexdigest()
                for folder in ('config','state') for path in (root/folder).iterdir()}

        original = digest()
        updater = Updater(root,source,isolated)
        try:
            isolated(updater.compose([old/'deploy/compose.yaml'])+['up','-d','--build','--wait','--wait-timeout','5'])
            updater.execute()
            assert digest()==original
            assert json.loads((root/'last-update.json').read_text())['commit']==first
            container = isolated(['docker','ps','-q','--filter','label=com.docker.compose.project=openvpnpa'],capture=True).strip()
            first_image = isolated(['docker','inspect','--format','{{.Image}}',container],capture=True).strip()
            assert isolated(['docker','exec',container,'cat','/var/lib/openvpnpa/traffic'],capture=True).strip()=='300'
            updater.execute()  # healthy same SHA: no restart
            compose['services']['node']['healthcheck']['test']=['CMD','false']
            (source/'deploy/compose.yaml').write_text(json.dumps(compose))
            with (source/'deploy/Dockerfile').open('a') as stream:
                stream.write('LABEL openvpnpa.test.revision="unhealthy"\n')
            commit()
            try:
                Updater(root,source,isolated).execute()
            except UpdateError as error:
                assert 'image ghabli bargasht' in str(error),str(error)
            else:
                raise AssertionError('Unhealthy replacement was not rejected')
            assert digest()==original
            assert json.loads((root/'last-update.json').read_text())['commit']==first
            container = isolated(['docker','ps','-q','--filter','label=com.docker.compose.project=openvpnpa'],capture=True).strip()
            health = isolated(['docker','inspect','--format','{{.State.Health.Status}}',container],capture=True).strip()
            assert health=='healthy',health
            assert isolated(['docker','inspect','--format','{{.Image}}',container],capture=True).strip()==first_image
            print('Live Docker update, same-commit no-op, rollback and config/state preservation PASSED')
        finally:
            if last_files:
                cleanup = ['docker','compose','--project-name',name]
                for file in last_files:
                    cleanup.extend(['-f',file])
                subprocess.run(cleanup+['down','--remove-orphans'],check=False)
            remaining = subprocess.check_output(['docker','ps','-aq','--filter',
                'label=com.docker.compose.project='+name],text=True).split()
            if remaining:
                subprocess.run(['docker','rm','-f',*remaining],check=False)
            subprocess.run(['docker','network','rm',name+'_default'],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for tag in tags:
                subprocess.run(['docker','image','rm',tag],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


if __name__=='__main__':
    main()
