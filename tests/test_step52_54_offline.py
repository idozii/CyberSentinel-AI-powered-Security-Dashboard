"""No-database regression for guarded CI-only custody, rollback and safety gate."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.step49_credential_broker import DisposableCredentialBroker
from scripts.step47_schema_rehearsal import DisposableSchemaRehearsal, TABLES
from scripts.step52_credential_custody import DisposableCredentialCustody
from scripts.step53_cutover_drill import DisposableCutoverDrill, Phase
from scripts.step54_readiness import assess
from scripts.install_step52_54 import install, PG_ANCHOR, UNIT_ANCHOR


class Step52_54Offline(unittest.TestCase):
    def _synthetic(self):
        scenario = object.__new__(DisposableSchemaRehearsal)
        scenario.created = True
        scenario.reverted = False
        scenario.roles = ('cs46_aaaaaaaaaaaa_a', 'cs46_aaaaaaaaaaaa_b')
        scenario.created_roles = list(scenario.roles)
        scenario._guard = Mock()
        broker = object.__new__(DisposableCredentialBroker)
        broker._scenario = scenario
        broker._guard = Mock()
        broker._ci_operator_rotate = Mock()
        broker._ci_operator_disable_and_terminate = Mock(return_value=2)
        broker._resolve = Mock(side_effect=lambda t: {'ci-a': 0, 'ci-b': 1}[t])
        custody = DisposableCredentialCustody(broker)
        drill = DisposableCutoverDrill(scenario, custody)
        drill._fixture_oracle = Mock(return_value={0:{t:1 for t in TABLES},1:{t:1 for t in TABLES}})
        drill._counts = Mock(return_value={t:1 for t in TABLES})
        return scenario, broker, custody, drill

    def test_custody_rejects_unrecognized_broker(self):
        with self.assertRaises(TypeError):
            DisposableCredentialCustody(object())

    def test_custody_operator_actions_have_redacted_audit(self):
        _, broker, custody, _ = self._synthetic()
        custody._ci_operator_rotate(0)
        self.assertEqual(custody._ci_operator_disable(1), 2)
        broker._ci_operator_rotate.assert_called_once_with(0)
        broker._ci_operator_disable_and_terminate.assert_called_once_with(1)
        audit = custody.report()
        self.assertEqual(audit['rotations'], 1)
        self.assertEqual(audit['disabled_fixture_logins'], 1)
        self.assertFalse(audit['managed_vault_integrated'])
        self.assertNotIn('password', json.dumps(audit).lower())
        with self.assertRaises(ValueError):
            custody._ci_operator_rotate(True)
        with self.assertRaises(ValueError):
            custody._ci_operator_disable(-1)

    def test_cutover_needs_two_shadow_probes_and_blocks_after_rollback(self):
        _, _, custody, drill = self._synthetic()
        with self.assertRaises(RuntimeError):
            drill.activate_canary()
        drill.begin_shadow()
        self.assertEqual(drill.shadow_probe('ci-a',0)['identities'], 1)
        with self.assertRaises(RuntimeError):
            drill.activate_canary()
        drill.shadow_probe('ci-b',1)
        drill.activate_canary()
        self.assertEqual(drill.phase, 'canary')
        drill.rollback('dependency_outage')
        self.assertEqual(drill.phase, 'rolled_back')
        self.assertFalse(custody.report()['enabled'])
        self.assertFalse(drill.report()['fallback_to_shared_runtime'])
        with self.assertRaises(RuntimeError):
            drill.canary_overview('ci-a')
        with self.assertRaises(RuntimeError):
            drill.begin_shadow()

    def test_token_tenant_mismatch_fails_closed_despite_identical_counts(self):
        _, _, custody, drill = self._synthetic()
        drill.begin_shadow()
        with self.assertRaises(AssertionError):
            drill.shadow_probe('ci-b', 0)
        self.assertEqual(drill.phase, Phase.ROLLED_BACK.value)
        self.assertFalse(custody.report()['enabled'])

    def test_unexpected_failure_reason_does_not_disable_without_valid_action(self):
        _, _, custody, drill = self._synthetic()
        drill.begin_shadow()
        with self.assertRaises(ValueError):
            drill.rollback('custom exception containing a secret')
        self.assertEqual(drill.phase, 'shadow')
        self.assertTrue(custody.report()['enabled'])

    def test_installer_is_idempotent_and_preserves_original_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root/'.github/workflows/ci.yml'
            p.parent.mkdir(parents=True)
            original = ('name: CI\n'
                        'test_step49_51_pg.py -v\n'
                        'test_step49_51_offline.py -v\n'
                        + UNIT_ANCHOR + PG_ANCHOR + 'trailer: retained\n')
            p.write_text(original)
            self.assertTrue(install(root, check_only=True))
            self.assertEqual(original, p.read_text())
            self.assertTrue(install(root))
            updated = p.read_text()
            self.assertFalse(install(root))
            self.assertEqual(updated, p.read_text())
            self.assertEqual(updated.count('test_step52_54_pg.py -v'),1)
            self.assertTrue(updated.endswith('trailer: retained\n'))

    def test_installer_fails_closed_if_previous_steps_missing(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'.github/workflows/ci.yml'
            p.parent.mkdir(parents=True)
            p.write_text('name: CI\n'+UNIT_ANCHOR+PG_ANCHOR)
            with self.assertRaises(RuntimeError):
                install(Path(td))

    def test_gate_declares_no_go_and_preserves_existing_staging(self):
        result = assess()
        self.assertEqual(result['status'],'ready_for_ci_review',result)
        self.assertTrue(all(result['checks'].values()),result)
        self.assertEqual(result['decision'],'NO_GO')
        self.assertFalse(result['public_beta_allowed'])
        self.assertFalse(result['managed_secret_vault'])
        self.assertFalse(result['staging_migrated'])


if __name__ == '__main__':
    unittest.main()
