"""Tests that the shipped skills relax and restore a PodDisruptionBudget in a form the API accepts.

    python3 -m unittest tests/test_skill_pdb_procedures.py

The API server rejects a PDB spec that sets both minAvailable and maxUnavailable, so a merge
patch that sets one has to clear the other in the same patch. A restore that re-applies a
`kubectl get pdb -o yaml` dump fails twice over: the dump's resourceVersion is stale once the
relax patch has run, so the apply gets a 409, and a three-way apply does not remove the field the
relax step added. gke-upgrades taught both forms until its synced copy registered corrections in
scripts/sync-upstream-skills.py. This reads every skill tree for the shapes it taught: a JSON or
YAML merge patch that relaxes a PDB to maxUnavailable 100% or restores minAvailable without
clearing the other field, and an apply of a file named as a PDB backup. It is a lexical guard, not
a parser: a patch body built by other means is not read.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_TREES = ("agents/platform/skills", "agents/cluster/skills", "a2a/persona/platform/skills")

# Flags kubectl accepts before or after the verb (`-n NAMESPACE`, `--context=X`).
FLAGS = r"(?:-{1,2}[\w-]+(?:[= ](?!pdb\b|poddisruptionbudgets?\b)[^\s-]\S*)?\s+)*"
# A `kubectl patch pdb` command, joined across backslash continuations.
PDB_PATCH_RE = re.compile(
    r"kubectl\s+" + FLAGS + r"patch\s+" + FLAGS + r"(pdb|poddisruptionbudgets?)\b(?:\\[ \t]*\n|[^\n])*"
)
# A field key in a JSON body (plain or shell-escaped quotes) or a YAML one.
KEY = r'(?:\\?"{field}\\?"|\b{field})\s*:\s*'
# The field set to a value other than null, and the same field cleared.
FIELD_SET_RE = KEY + r"(?!null)"
CLEARED_RE = KEY + r"null"
# The relax: maxUnavailable opened to 100%.
RELAX_RE = KEY.format(field="maxUnavailable") + r'\\?["\']?100%'
# Applying a file named as a PDB backup or dump.
PDB_DUMP_APPLY_RE = re.compile(
    r"kubectl\s+" + FLAGS + r"apply\s+" + FLAGS + r"-f\s+\S*(?:pdb\S*(?:backup|bak|dump|orig|saved)|(?:backup|bak|dump|orig|saved)\S*pdb)\S*",
    re.IGNORECASE,
)


def _skill_files():
    for tree in SKILL_TREES:
        yield from sorted((REPO_ROOT / tree).rglob("*.md"))


def _bad_patches(text):
    # A restore to a maxUnavailable-only PDB legitimately sets maxUnavailable alone: the relax
    # step already cleared minAvailable. So the rule binds the restore to minAvailable and the
    # relax, which is the patch that opens the PDB to 100%.
    bad = []
    for match in PDB_PATCH_RE.finditer(text):
        patch = match.group(0)
        sets_min = re.search(FIELD_SET_RE.format(field="minAvailable"), patch)
        relaxes = re.search(RELAX_RE, patch)
        if (sets_min and not re.search(CLEARED_RE.format(field="maxUnavailable"), patch)) or (
            relaxes and not re.search(CLEARED_RE.format(field="minAvailable"), patch)
        ):
            bad.append(patch)
    return bad


class PdbProceduresTest(unittest.TestCase):
    def test_a_pdb_patch_clears_the_field_it_does_not_set(self):
        offenders = [
            f"{path.relative_to(REPO_ROOT)}: {patch!r}"
            for path in _skill_files()
            for patch in _bad_patches(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_no_pdb_is_restored_by_applying_a_dump(self):
        offenders = [
            f"{path.relative_to(REPO_ROOT)}: {match.group(0)}"
            for path in _skill_files()
            for match in PDB_DUMP_APPLY_RE.finditer(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])


class PdbGuardShapesTest(unittest.TestCase):
    """The guard reads the spellings a skill could teach, not only the ones gke-upgrades used."""

    def test_flagged(self):
        for text in [
            """kubectl patch pdb web -p '{"spec":{"maxUnavailable":"100%"}}'""",
            """kubectl -n shop patch pdb web --type merge -p '{"spec":{"maxUnavailable":"100%"}}'""",
            """kubectl patch -n shop pdb web --type merge \\ \n  -p '{"spec":{"maxUnavailable":"100%"}}'""",
            r'kubectl patch pdb web -p "{\"spec\":{\"maxUnavailable\":\"100%\"}}"',
            """kubectl patch pdb web -p 'spec: {maxUnavailable: "100%"}'""",
            """kubectl patch poddisruptionbudget web -p '{"spec":{"minAvailable":2}}'""",
        ]:
            with self.subTest(text=text):
                self.assertTrue(_bad_patches(text))

    def test_passed(self):
        for text in [
            """kubectl -n shop patch pdb web -p '{"spec":{"minAvailable":null,"maxUnavailable":"100%"}}'""",
            """kubectl patch pdb web -p '{"spec":{"maxUnavailable":null,"minAvailable":2}}'""",
            """kubectl patch pdb web -p '{"spec":{"maxUnavailable":1}}'""",
        ]:
            with self.subTest(text=text):
                self.assertFalse(_bad_patches(text))

    def test_dump_apply(self):
        self.assertTrue(PDB_DUMP_APPLY_RE.search("kubectl apply -f pdb-backup.yaml"))
        self.assertTrue(PDB_DUMP_APPLY_RE.search("kubectl -n shop apply -f /tmp/backup-web-pdb.yaml"))
        self.assertFalse(PDB_DUMP_APPLY_RE.search("kubectl apply -f web-pdb.yaml"))


if __name__ == "__main__":
    unittest.main()
