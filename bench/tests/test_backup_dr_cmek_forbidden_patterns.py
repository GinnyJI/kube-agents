"""backup-dr-cmek-selected-namespaces-probe forbids the rejected flags in use, not in mention.

The report_contains verifier ``re.search``es each forbidden pattern over
``_normalize_lines``: lowercased, Markdown emphasis and backticks dropped,
newlines kept. A substring would fail ``--enable-gke-backup-plan`` and a
sentence that rules a flag out, so each pattern needs the flag bounded and
followed by ``=``, or by at most one value before a continuation or the line's
end.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from kube_agents_bench.verifiers import _normalize_lines

TASK = Path(__file__).resolve().parent.parent / "tasks" / "backup-dr-cmek-selected-namespaces-probe" / "task.yaml"
CHECK = "the-plan-uses-the-real-flags"


def _forbidden(report: str) -> bool:
    doc = yaml.safe_load(TASK.read_text())
    (check,) = [c for c in doc["verification_spec"] if c.get("name") == CHECK]
    return any(re.search(p, _normalize_lines(report)) for p in check["check"]["forbidden_patterns"])


def test_rejected_flags_in_commands_are_forbidden():
    for report in (
        "```\ngcloud container clusters update prod-1 \\\n  --enable-gke-backup \\\n  --location=us-central1\n```",
        "gcloud container clusters update prod-1 --location=us-central1 --enable-gke-backup",
        "  --retention-days=30 \\",
        "  --retention-days 30 \\",
        "gcloud beta container backup-restore backup-plans create p --included-namespaces=payments,ledger",
        "  --backup-encryption-key=projects/p/locations/us-central1/keyRings/k/cryptoKeys/gke",
    ):
        assert _forbidden(report), report


def test_bounded_flags_and_mentions_are_not_forbidden():
    for report in (
        "./install.sh --enable-gke-backup-plan",
        "The plan keeps each backup 30 days via `--backup-retain-days`, not `--retention-days`.",
        "Use `--selected-namespaces`; `--included-namespaces` does not exist.",
        "  --encryption-key=projects/p/locations/us-central1/keyRings/k/cryptoKeys/gke \\",
        "gcloud container clusters update prod-1 --update-addons=BackupRestore=ENABLED --location=us-central1",
    ):
        assert not _forbidden(report), report
