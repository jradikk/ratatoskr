"""Offline contract checks for GitHub-owned publication; never build or push."""
from pathlib import Path
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]


def workflow(name):
    return yaml.load((ROOT / '.github/workflows' / name).read_text(), Loader=yaml.BaseLoader)


class GitHubReleaseTests(unittest.TestCase):
    def test_version_tags_only_and_reusable_validation(self):
        release = workflow('release.yaml')
        self.assertEqual(release['on'], {'push': {'tags': ['v*.*.*']}})
        ci = workflow('ci.yaml')
        self.assertIn('workflow_call', ci['on'])
        self.assertNotIn('tags', ci['on']['push'])
        self.assertEqual(release['jobs']['test']['uses'], './.github/workflows/ci.yaml')
        self.assertEqual(release['concurrency']['cancel-in-progress'], 'false')

    def test_all_six_images_and_matching_chart(self):
        jobs = workflow('release.yaml')['jobs']
        self.assertEqual(jobs['images']['strategy']['matrix']['component'],
                         ['controller', 'webhook', 'agent', 'gateway', 'init', 'upstream-openvpn'])
        build = next(s for s in jobs['images']['steps'] if s.get('id') == 'push')
        self.assertEqual(build['with']['platforms'], 'linux/amd64,linux/arm64')
        self.assertEqual(build['with']['push'], 'true')
        self.assertEqual(build['with']['sbom'], 'true')
        self.assertEqual(build['with']['provenance'], 'mode=max')
        self.assertIn('docker.io/${{ github.repository_owner }}', build['with']['tags'])
        self.assertTrue({'images', 'binaries', 'test', 'validate'} <= set(jobs['chart']['needs']))
        staging = next(s['run'] for s in jobs['chart']['steps'] if s.get('name', '').startswith('Package chart'))
        self.assertIn('docker.io/jradikk', staging)
        self.assertIn('jradikk/ratatoskr', staging)
        self.assertNotIn('ghcr.io/skaldhall', staging)
        self.assertNotIn('values.write_text', staging)
        self.assertIn('--app-version "$RELEASE_VERSION"', staging)
        self.assertEqual(set(jobs['publish']['needs']), {'validate', 'images', 'binaries', 'chart'})

    def test_publication_does_not_require_acceptance_ledger(self):
        release = workflow('release.yaml')
        for job in release['jobs'].values():
            for step in job.get('steps', []):
                self.assertNotIn('release_acceptance.py', step.get('run', ''))
                self.assertNotIn('--require-ready', step.get('run', ''))

    def test_credentials_and_attestation_failures_are_not_ignored(self):
        jobs = workflow('release.yaml')['jobs']
        login = next(s for s in jobs['images']['steps'] if s.get('uses') == 'docker/login-action@v3')
        self.assertEqual(login['with']['username'], '${{ secrets.DOCKER_USERNAME }}')
        self.assertEqual(login['with']['password'], '${{ secrets.DOCKER_PASSWORD }}')
        for job in ('images', 'binaries', 'chart'):
            attest = next(s for s in jobs[job]['steps'] if s.get('uses', '').startswith('actions/attest-build-provenance@'))
            self.assertNotIn('continue-on-error', attest)
            self.assertEqual(jobs[job]['permissions']['id-token'], 'write')
        self.assertEqual(jobs['publish']['permissions'], {'contents': 'write'})
        self.assertEqual(jobs['images']['permissions']['contents'], 'read')

    def test_embedded_shell_syntax(self):
        for name in ('ci.yaml', 'release.yaml'):
            for job in workflow(name)['jobs'].values():
                for step in job.get('steps', []):
                    if 'run' not in step:
                        continue
                    result = subprocess.run(['bash', '-n'], input=step['run'], text=True,
                                            capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_canonical_tag_validation(self):
        script = workflow('release.yaml')['jobs']['validate']['steps'][1]['run']
        # Run only the tag regex; do not write Actions outputs or build artifacts.
        regex = next(line for line in script.splitlines() if line.startswith('[['))
        for tag, valid in [('v0.1.0', True), ('v0.1.0-rc.1', True), ('0.1.0', False),
                           ('v01.1.0', False), ('v0.1.0-rc.0', False), ('v0.1.0;echo x', False)]:
            result = subprocess.run(['bash', '-c', regex], env={'RELEASE_TAG': tag}, timeout=5)
            self.assertEqual(result.returncode == 0, valid, tag)
