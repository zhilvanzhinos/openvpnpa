"""Shell bootstrap regression checks; package/daemon commands are isolated stubs."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base/'installed'
        self.bin = self.base/'bin'
        self.bin.mkdir()
        (self.root/'config').mkdir(parents=True)
        (self.root/'config/config.json').write_text('{"existing":"preserve-me"}')
        (self.root/'config/compose.env').write_text('UI_BIND=127.0.0.1\n')
        self.environment = dict(os.environ,PATH=str(self.bin)+':/usr/bin:/bin',
            BOOT_TEST_BASE=str(self.base),BOOT_DOCKER_MISSING='0',BOOT_COMPOSE_MISSING='0',
            BOOT_NODE_EXISTS='1',BOOT_PREPARE_FAIL='0')
        self.tool('docker','''
if [[ "$1" == compose && "$2" == version && "$BOOT_COMPOSE_MISSING" == 1 && ! -f "$BOOT_TEST_BASE/ready" ]]; then exit 1; fi
if [[ "$1" == ps && "$BOOT_NODE_EXISTS" == 1 ]]; then echo node-container; fi
exit 0
''')
        self.tool('git','mkdir -p "${@: -1}"\n')
        self.tool('python3','touch "$BOOT_TEST_BASE/updater-ran"\n')
        self.tool('curl','cp "$BOOT_TEST_BASE/installer-stub" "$4"\n')
        (self.base/'installer-stub').write_text('''#!/usr/bin/env bash
if [[ ${1:-} == --prepare-only ]]; then
  touch "$BOOT_TEST_BASE/prepared"
  [[ "$BOOT_PREPARE_FAIL" == 0 ]] || exit 7
  touch "$BOOT_TEST_BASE/ready"
else
  touch "$BOOT_TEST_BASE/full-install"
fi
''')

    def tearDown(self):
        self.tmp.cleanup()

    def tool(self, name, body):
        path = self.bin/name
        path.write_text('#!/usr/bin/env bash\nset -euo pipefail\n'+body)
        path.chmod(0o700)

    def invoke(self):
        script = (PROJECT/'update.sh').read_text().replace('/opt/openvpnpa',str(self.root))
        script = '\n'.join(':' if line.startswith('[[ $EUID -eq 0 ]]') else line for line in script.splitlines())
        # The binary exists as a stub, but command -v models a missing CLI until
        # the prerequisite installer has completed. No real apt/docker is run.
        prefix = '''command() {
if [[ ${1:-} == -v && ${2:-} == docker && "$BOOT_DOCKER_MISSING" == 1 && ! -f "$BOOT_TEST_BASE/ready" ]]; then return 1; fi
builtin command "$@"
}
'''
        return subprocess.run(['bash','-c',prefix+script],env=self.environment,
            capture_output=True,text=True,timeout=10)

    def test_missing_docker_is_prepared_before_normal_update(self):
        self.environment['BOOT_DOCKER_MISSING']='1'
        result = self.invoke()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.base/'prepared').exists())
        self.assertTrue((self.base/'updater-ran').exists())
        self.assertFalse((self.base/'full-install').exists())
        self.assertEqual((self.root/'config/config.json').read_text(),'{"existing":"preserve-me"}')

    def test_missing_compose_is_prepared_without_reconfiguring_application(self):
        self.environment['BOOT_COMPOSE_MISSING']='1'
        result = self.invoke()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.base/'prepared').exists())
        self.assertTrue((self.base/'updater-ran').exists())
        self.assertFalse((self.base/'full-install').exists())

    def test_incomplete_configuration_resumes_full_installer(self):
        (self.root/'config/compose.env').unlink()
        result = self.invoke()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.base/'full-install').exists())
        self.assertFalse((self.base/'updater-ran').exists())
        self.assertEqual((self.root/'config/config.json').read_text(),'{"existing":"preserve-me"}')

    def test_missing_container_resumes_installation(self):
        self.environment['BOOT_NODE_EXISTS']='0'
        result = self.invoke()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.base/'full-install').exists())
        self.assertFalse((self.base/'updater-ran').exists())

    def test_prerequisite_failure_does_not_attempt_deployment(self):
        self.environment.update(BOOT_DOCKER_MISSING='1',BOOT_PREPARE_FAIL='1')
        result = self.invoke()
        self.assertEqual(result.returncode,7)
        self.assertFalse((self.base/'updater-ran').exists())
        self.assertFalse((self.base/'full-install').exists())


class PrerequisiteTests(unittest.TestCase):
    def run_prepare(self, missing=False, compose_missing=False, vendor='io', active=False):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            tools = base/'bin'
            tools.mkdir()
            root = base/'installed'
            (root/'config').mkdir(parents=True)
            (root/'config/config.json').write_text('preserve-private-configuration')
            (base/'os-release').write_text('ID=ubuntu\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"\n')
            def tool(name, body):
                path = tools/name
                path.write_text('#!/usr/bin/env bash\nset -euo pipefail\n'+body)
                path.chmod(0o700)
            tool('apt-get','''echo "apt $*" >> "$BOOT_TEST_BASE/commands"
if [[ "$*" == *docker.io* || "$*" == *docker-ce-cli* ]]; then touch "$BOOT_TEST_BASE/docker-ready"; fi
if [[ "$*" == *docker-compose* ]]; then touch "$BOOT_TEST_BASE/compose-ready"; fi
''')
            tool('pgrep','[[ "$BOOT_ACTIVE" == 1 ]]\n')
            tool('systemctl','echo "systemctl $*" >> "$BOOT_TEST_BASE/commands"\n')
            tool('dpkg-query','''if [[ "$BOOT_VENDOR" == ce && "${@: -1}" == docker-ce-cli || "$BOOT_VENDOR" == io && "${@: -1}" == docker.io ]]; then echo 'install ok installed'; else exit 1; fi
''')
            tool('docker','''if [[ "$1" == compose && ! -f "$BOOT_TEST_BASE/compose-ready" ]]; then exit 1; fi
if [[ "$1" == info && ! -f "$BOOT_TEST_BASE/docker-ready" ]]; then exit 1; fi
exit 0
''')
            if not missing:
                (base/'docker-ready').touch()
            if not compose_missing:
                (base/'compose-ready').touch()
            script = (PROJECT/'install.sh').read_text().replace('/opt/openvpnpa',str(root))
            script = script.replace('source /etc/os-release','source "$BOOT_TEST_BASE/os-release"')
            script = script.replace('[[ -c /dev/net/tun ]]','true')
            script = '\n'.join(':' if line.startswith('[[ $EUID -eq 0 ]]') else line for line in script.splitlines())
            prefix = '''command() {
if [[ ${1:-} == -v && ${2:-} == docker && ! -f "$BOOT_TEST_BASE/docker-ready" ]]; then return 1; fi
builtin command "$@"
}
'''
            environment = dict(os.environ,PATH=str(tools)+':/usr/bin:/bin',BOOT_TEST_BASE=str(base),
                BOOT_VENDOR=vendor,BOOT_ACTIVE='1' if active else '0')
            result = subprocess.run(['bash','-c',prefix+script,'prepare-test','--prepare-only'],
                env=environment,capture_output=True,text=True,timeout=10)
            self.assertEqual((root/'config/config.json').read_text(),'preserve-private-configuration')
            self.assertFalse((root/'releases').exists())
            return result,(base/'commands').read_text()

    def test_new_docker_install_uses_ubuntu_packages_and_preserves_configuration(self):
        result,commands = self.run_prepare(missing=True,compose_missing=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('docker.io docker-compose-v2',commands)
        self.assertIn('systemctl enable --now docker',commands)

    def test_docker_ce_gets_matching_compose_plugin_without_daemon_restart(self):
        result,commands = self.run_prepare(compose_missing=True,vendor='ce')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('docker-compose-plugin',commands)
        self.assertNotIn('docker.io',commands)
        self.assertNotIn('systemctl',commands)

    def test_ubuntu_docker_gets_matching_compose_v2(self):
        result,commands = self.run_prepare(compose_missing=True,vendor='io')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('docker-compose-v2',commands)
        self.assertNotIn('systemctl',commands)

    def test_active_daemon_without_cli_is_not_replaced(self):
        result,commands = self.run_prepare(missing=True,active=True)
        self.assertEqual(result.returncode,1)
        self.assertIn('daemon faal ast',result.stderr)
        self.assertNotIn('docker.io',commands)
        self.assertNotIn('systemctl',commands)


if __name__=='__main__':
    unittest.main()
