"""Guard project migration, canonical R1 bytes, and local documentation links."""
import hashlib
import json
from pathlib import Path
import re
import unittest
from .script import assemble

ROOT=Path(__file__).resolve().parents[1]


class LayoutTests(unittest.TestCase):
    def test_r1_canonical_bytes_unchanged(self):
        project=ROOT/'projects/p2pkh-r1'
        layout=json.loads((project/'template/layout.json').read_text())
        raw=bytes.fromhex((project/'template/template.hex').read_text())
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'b3acd6b92a23120bd24432ada2b1cac013fe06381d7ea96ac6c5a73c493f4287')
        for vector in layout['vectors']:
            owner=bytes.fromhex(vector['owner_hash160']); rebuilt=assemble(project/'reference/asm',owner)
            self.assertEqual(hashlib.sha256(rebuilt).hexdigest(),vector['script_sha256'])
            self.assertEqual(rebuilt,raw[:208]+owner+raw[228:])

    def test_project_resources_and_local_links(self):
        for name in ('p2pkh-r1','p2pkh-r1-deferred','p2pkh-sm2'):
            for child in ('README.md','docs','reference','template'):
                self.assertTrue((ROOT/'projects'/name/child).exists())
        for path in ROOT.rglob('*.md'):
            for target in re.findall(r'\]\(([^)]+)\)',path.read_text()):
                if ':' in target or target.startswith('#'): continue
                target=target.split('#')[0]
                self.assertTrue((path.parent/target).exists(),f'{path.relative_to(ROOT)} -> {target}')

if __name__=='__main__': unittest.main()
