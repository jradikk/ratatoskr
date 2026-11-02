"""Offline regression checks for release-facing documentation and metadata."""
from pathlib import Path
import re
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]


class PublicDocumentationTests(unittest.TestCase):
    def test_public_guides_do_not_expose_milestone_or_staging_notes(self):
        guides = [ROOT / name for name in ('README.md', 'CONTRIBUTING.md', 'SECURITY.md')]
        for directory in ('docs', 'charts', 'pkg', 'plugins', 'bpf'):
            guides.extend((ROOT / directory).rglob('*.md'))
        for path in guides:
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertNotRegex(path.read_text(), r'\bM\d+\b|(?i:pre-alpha|package staging|EXECUTION DEFERRED)')

    def test_relative_documentation_links_resolve(self):
        paths = [ROOT / 'README.md', ROOT / 'CONTRIBUTING.md', ROOT / 'SECURITY.md',
                 ROOT / '.github/RELEASING.md']
        for directory in ('docs', 'charts', 'pkg', 'plugins', 'bpf'):
            paths.extend((ROOT / directory).rglob('*.md'))
        for path in paths:
            for target in re.findall(r'\]\(([^)]+)\)', path.read_text()):
                target = target.split('#')[0]
                if not target or '://' in target or target.startswith('mailto:'):
                    continue
                with self.subTest(path=str(path.relative_to(ROOT)), target=target):
                    self.assertTrue((path.parent / target).exists())

    def test_source_chart_uses_release_metadata_and_registry(self):
        chart = yaml.safe_load((ROOT / 'charts/ratatoskr/Chart.yaml').read_text())
        values = yaml.safe_load((ROOT / 'charts/ratatoskr/values.yaml').read_text())
        self.assertRegex(chart['version'], r'^\d+\.\d+\.\d+$')
        self.assertEqual(str(chart['appVersion']), chart['version'])
        self.assertEqual(values['image']['registry'], 'docker.io/jradikk')
        self.assertEqual(chart['home'], 'https://github.com/jradikk/ratatoskr')
        self.assertEqual(chart['sources'], ['https://github.com/jradikk/ratatoskr'])

    def test_local_make_targets_cannot_push_images(self):
        command = subprocess.run(['make', '-n', 'images-multiarch', 'PUSH=1'],
                                 cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(command.returncode, 0, command.stderr)
        self.assertNotIn('--push', command.stdout)
        self.assertIn('upstream-', command.stdout)
        for name in ('build-experimental-rc.py', 'build-production-artifacts.py', 'prepare-release.py'):
            self.assertFalse((ROOT / 'hack' / name).exists())

    def test_container_source_labels_match_repository(self):
        for name in ('Dockerfile', 'plugins/upstream/openvpn/Dockerfile'):
            self.assertIn('org.opencontainers.image.source="https://github.com/jradikk/ratatoskr"',
                          (ROOT / name).read_text())


if __name__ == '__main__':
    unittest.main()
