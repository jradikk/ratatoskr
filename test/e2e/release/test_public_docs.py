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
        self.assertEqual(values['image']['registry'], 'ghcr.io/jradikk')
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

    def test_dashboard_connection_protocols_match_collector(self):
        import json
        dashboard = json.loads((ROOT / 'dashboards/ratatoskr-overview.json').read_text())
        expressions = [target.get('expr', '') for panel in dashboard['panels']
                       for target in panel.get('targets', [])]
        connections = [expr for expr in expressions if 'ratatoskr_gateway_forwarded_connections' in expr]
        self.assertTrue(any('protocol="TCP"' in expr for expr in connections))
        self.assertTrue(any('protocol="UDP"' in expr for expr in connections))
        self.assertFalse(any('protocol="tcp"' in expr or 'protocol="udp"' in expr for expr in connections))
        self.assertEqual((ROOT / 'dashboards/ratatoskr-overview.json').read_bytes(),
                         (ROOT / 'charts/ratatoskr/dashboards/ratatoskr-overview.json').read_bytes())

    def test_chart_metrics_addresses_match_runtime_contract(self):
        workloads = (ROOT / 'charts/ratatoskr/templates/workloads.yaml').read_text()
        agent = (ROOT / 'charts/ratatoskr/templates/agent.yaml').read_text()
        for port, template in ((8080, workloads), (9904, workloads), (9903, agent)):
            self.assertIn('ternary "0.0.0.0:%s" "0"' % port, template)
            self.assertNotIn('ternary ":%s"' % port, template)

    def test_domain_crd_label_limits_do_not_use_expensive_cel_loops(self):
        crd = yaml.safe_load((ROOT / 'charts/ratatoskr/crds/ratatoskr.skaldhall.io_egresspolicies.yaml').read_text())
        selector = crd['spec']['versions'][0]['schema']['openAPIV3Schema']['properties']['spec']['properties']['rules']['items']['properties']['domains']['items']
        self.assertEqual(len(selector['x-kubernetes-validations']), 1)
        self.assertNotIn('split(', selector['x-kubernetes-validations'][0]['rule'])
        for field in ('matchName', 'matchPattern'):
            pattern = selector['properties'][field]['pattern']
            prefix = '*.' if field == 'matchPattern' else ''
            self.assertIsNotNone(re.fullmatch(pattern, prefix + 'a' * 63 + '.example.com'))
            self.assertIsNone(re.fullmatch(pattern, prefix + 'a' * 64 + '.example.com'))
            self.assertIsNone(re.fullmatch(pattern, prefix + 'bad-.example.com'))
            self.assertIsNone(re.fullmatch(pattern, prefix + 'UPPER.example.com'))

    def test_container_source_labels_match_repository(self):
        for name in ('Dockerfile', 'plugins/upstream/openvpn/Dockerfile'):
            self.assertIn('org.opencontainers.image.source="https://github.com/jradikk/ratatoskr"',
                          (ROOT / name).read_text())


if __name__ == '__main__':
    unittest.main()
