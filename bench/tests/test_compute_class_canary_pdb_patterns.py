"""compute-class-canary-active-migration-pdb-probe reads its selector and budget from one PDB document.

The report_contains verifier ``re.search``es each ``any_of_patterns`` entry over
``_normalize_lines``: lowercased, Markdown emphasis and backticks dropped,
leading indentation collapsed to one space, newlines kept. A presence check
over the whole report would let a Deployment's selector or its
``rollingUpdate.maxUnavailable: 0`` stand in for the PDB's, so the pattern
starts at ``kind: PodDisruptionBudget`` and stops at the next YAML document:
``---``, a second ``kind:``, or the blank line a closing code fence leaves once
normalization has deleted its backticks. Both halves are lookaheads from that
one start, so a second PDB cannot supply the half the first one lacks.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from kube_agents_bench.verifiers import _normalize_lines

TASK = Path(__file__).resolve().parent.parent / "tasks" / "compute-class-canary-active-migration-pdb-probe" / "task.yaml"
CHECK = "the-green-pdb-refuses-every-eviction"

PDB_HEAD = "```yaml\napiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: shop-green-pdb\n"
DEPLOYMENT = (
    "---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: shop-green\n  labels:\n    app: shop\n"
    "    version: green\nspec:\n  strategy:\n    rollingUpdate:\n      maxUnavailable: 0\n  selector:\n"
    "    matchLabels:\n      app: shop\n      version: green\n"
)


def _matches(report: str) -> bool:
    doc = yaml.safe_load(TASK.read_text())
    (check,) = [c for c in doc["verification_spec"] if c.get("name") == CHECK]
    return any(re.search(p, _normalize_lines(report)) for p in check["check"]["any_of_patterns"])


def test_a_version_scoped_zero_budget_pdb_passes():
    for spec in (
        "spec:\n  maxUnavailable: 0\n  selector:\n    matchLabels:\n      app: shop\n      version: green\n```",
        'spec:\n  maxUnavailable: "0"\n  selector:\n    matchLabels:\n      app: shop\n      version: "green"\n```',
        "spec:\n  minAvailable: 100%\n  selector:\n    matchLabels: {app: shop, version: green}\n```",
        "spec:\n  selector: {matchLabels: {app: shop, version: green}}\n  maxUnavailable: 0\n```",
        "spec:\n  maxUnavailable: 0\n  selector:\n    matchExpressions:\n    - key: version\n      operator: In\n"
        "      values: [green]\n```",
        "spec:\n  maxUnavailable: 0\n  selector:\n    matchExpressions:\n    - key: version\n      operator: In\n"
        "      values:\n      - green\n```",
        "spec:\n  selector:\n    matchExpressions:\n    - operator: In\n      key: version\n      values: [green]\n"
        "  maxUnavailable: 0\n```",
    ):
        report = PDB_HEAD + spec
        assert _matches(report), report


def test_another_documents_tokens_do_not_stand_in_for_the_pdb():
    # The PDB selects app: shop only and keeps a 25% budget; the version label
    # and the zero budget belong to the Deployment that follows it.
    loose = PDB_HEAD + "spec:\n  maxUnavailable: 25%\n  selector:\n    matchLabels:\n      app: shop\n" + DEPLOYMENT + "```"
    assert not _matches(loose)
    # A Deployment alone, with the PDB only named in prose.
    prose = "Create a PodDisruptionBudget for the canary.\n```yaml\n" + DEPLOYMENT + "```"
    assert not _matches(prose)


def test_the_pdbs_own_metadata_labels_are_not_its_selector():
    report = (
        PDB_HEAD
        + "  labels:\n    app: shop\n    version: green\nspec:\n  maxUnavailable: 0\n  selector:\n    matchLabels:\n      app: shop\n```"
    )
    assert not _matches(report)


def test_a_quoted_or_json_pdb_passes():
    quoted = PDB_HEAD.replace("kind: PodDisruptionBudget", 'kind: "PodDisruptionBudget"') + (
        "spec:\n  maxUnavailable: 0\n  selector:\n    matchLabels:\n      app: shop\n      version: green\n```"
    )
    json_pdb = (
        '```json\n{"apiVersion": "policy/v1", "kind": "PodDisruptionBudget", "metadata": {"name": "shop-green-pdb"},\n'
        ' "spec": {"maxUnavailable": 0, "selector": {"matchLabels": {"app": "shop", "version": "green"}}}}\n```'
    )
    for report in (quoted, json_pdb):
        assert _matches(report), report


def test_prose_after_a_closed_fence_does_not_stand_in_for_the_pdb():
    # The PDB selects app: shop only and keeps a 25% budget, and nothing after it
    # opens with --- or kind:; the version label and the zero budget come from
    # prose and a fenced fragment after the manifest's closing fence.
    loose = PDB_HEAD + "spec:\n  maxUnavailable: 25%\n  selector:\n    matchLabels:\n      app: shop\n```\n"
    for tail in (
        "It selects app: shop, version: green and blue alike. A `maxUnavailable: 0` budget would block rollouts.",
        "Your Deployment already selects:\n```yaml\nselector:\n  matchLabels:\n    app: shop\n    version: green\n"
        "rollingUpdate:\n  maxUnavailable: 0\n```",
    ):
        assert not _matches(loose + tail), tail


def test_a_notin_expression_is_not_a_version_scoped_selector():
    report = PDB_HEAD + (
        "spec:\n  maxUnavailable: 0\n  selector:\n    matchExpressions:\n    - key: version\n      operator: NotIn\n"
        "      values: [green]\n```"
    )
    assert not _matches(report)


def test_two_pdbs_do_not_add_up_to_one_green_pdb_at_zero():
    # The zero budget guards blue and the green PDB keeps 25%: each half is in
    # some PDB, but no one PDB holds both.
    blue_guard = PDB_HEAD.replace("shop-green-pdb", "shop-blue-guard") + (
        "spec:\n  maxUnavailable: 0\n  selector:\n    matchLabels:\n      app: shop\n      version: blue\n"
    )
    green = "---\napiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: shop-green\n" + (
        "spec:\n  maxUnavailable: 25%\n  selector:\n    matchLabels:\n      app: shop\n      version: green\n```"
    )
    assert not _matches(blue_guard + green)
    app_only = blue_guard.replace("      version: blue\n", "")
    assert not _matches(app_only + green)


def test_the_words_kind_poddisruptionbudget_in_prose_do_not_open_a_document():
    report = (
        "Create a kind: PodDisruptionBudget whose selector is\n```yaml\nselector:\n  matchLabels:\n    app: shop\n"
        "    version: green\nmaxUnavailable: 0\n```"
    )
    assert not _matches(report)
