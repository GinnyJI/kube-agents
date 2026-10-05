"""Tests that the shipped skills relax and restore a PodDisruptionBudget in a form the API accepts.

    python3 -m unittest tests/test_skill_pdb_procedures.py

The API server rejects a PDB spec that sets both minAvailable and maxUnavailable, so a merge
patch that sets one has to clear the other in the same patch. A restore that re-applies a
`kubectl get pdb -o yaml` dump fails twice over: the dump's resourceVersion is stale once the
relax patch has run, so the apply gets a 409, and a three-way apply does not remove the field the
relax step added. gke-upgrades taught both forms until its synced copy registered corrections in
scripts/sync-upstream-skills.py; this reads every skill tree for them.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_TREES = ("agents/platform/skills", "agents/cluster/skills", "a2a/persona/platform/skills")

# A `kubectl patch pdb` command, joined across backslash continuations.
PDB_PATCH_RE = re.compile(r"kubectl\s+patch\s+(pdb|poddisruptionbudgets?)\b(?:\\\n|[^\n])*")
# A JSON field set to a value other than null, and the same field cleared.
FIELD_SET_RE = r'"{field}"\s*:\s*(?!null)'
CLEARED_RE = r'"{field}"\s*:\s*null'
# The relax: maxUnavailable opened to 100%.
RELAX_RE = r'"maxUnavailable"\s*:\s*"100%"'
# Applying a file named as a PDB backup.
PDB_DUMP_APPLY_RE = re.compile(r"kubectl\s+apply\s+-f\s+\S*pdb\S*", re.IGNORECASE)


def _skill_files():
    for tree in SKILL_TREES:
        yield from sorted((REPO_ROOT / tree).rglob("*.md"))


class PdbProceduresTest(unittest.TestCase):
    def test_a_pdb_patch_clears_the_field_it_does_not_set(self):
        # A restore to a maxUnavailable-only PDB legitimately sets maxUnavailable alone: the relax
        # step already cleared minAvailable. So the rule binds the restore to minAvailable and the
        # relax, which is the patch that opens the PDB to 100%.
        offenders = []
        for path in _skill_files():
            for match in PDB_PATCH_RE.finditer(path.read_text(encoding="utf-8")):
                patch = match.group(0)
                sets_min = re.search(FIELD_SET_RE.format(field="minAvailable"), patch)
                relaxes = re.search(RELAX_RE, patch)
                if (sets_min and not re.search(CLEARED_RE.format(field="maxUnavailable"), patch)) or (
                    relaxes and not re.search(CLEARED_RE.format(field="minAvailable"), patch)
                ):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {patch!r}")
        self.assertEqual(offenders, [])

    def test_no_pdb_is_restored_by_applying_a_dump(self):
        offenders = [
            f"{path.relative_to(REPO_ROOT)}: {match.group(0)}"
            for path in _skill_files()
            for match in PDB_DUMP_APPLY_RE.finditer(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
