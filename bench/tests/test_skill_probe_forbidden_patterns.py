"""The skill-sync probes' forbidden patterns flag a command, not a mention of it.

``report_contains`` strips backticks, ``*`` and ``_`` before it runs a
forbidden pattern, so a report line that only names the ruled-out command
starts at column 0 exactly as the command itself would. These pin each
pattern against both shapes, run through the verifier's own normalisation.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from kube_agents_bench.verifiers import _normalize_lines

TASKS = Path(__file__).resolve().parent.parent / "tasks"


def _flagged(case, check, report):
    doc = yaml.safe_load((TASKS / case / "task.yaml").read_text())
    (spec,) = [c for c in doc["verification_spec"] if c.get("name") == check]
    text = _normalize_lines(report)
    return any(re.search(p, text) for p in spec["check"]["forbidden_patterns"])


WI = ("workload-identity-signed-url-probe", "the-fix-is-the-return-principal-id-as-email-annotation")


def test_wi_probe_flags_minting_a_key():
    for report in (
        "gcloud iam service-accounts keys create key.json --iam-account=sa@p.iam.gserviceaccount.com",
        "```bash\n$ gcloud iam service-accounts keys create KEY_FILE \\\n  --iam-account=SA_EMAIL\n```",
        "* `gcloud iam service-accounts keys create /tmp/key.json`",
        "  gcloud iam service-accounts keys create --iam-account=sa@p.iam.gserviceaccount.com key.json",
    ):
        assert _flagged(*WI, report), report


def test_wi_probe_passes_a_report_that_rules_the_key_out():
    for report in (
        "`gcloud iam service-accounts keys create` is ruled out; annotate the KSA instead.",
        "* `gcloud iam service-accounts keys create` would work but mints a long-lived key.",
        "Do not fall back to gcloud iam service-accounts keys create key.json --iam-account=x.",
        "**gcloud iam service-accounts keys create** is not needed.",
    ):
        assert not _flagged(*WI, report), report
