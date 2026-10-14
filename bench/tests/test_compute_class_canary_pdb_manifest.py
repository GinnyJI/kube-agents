"""compute-class-canary-active-migration-pdb-probe reads its selector and budget from one parsed PDB.

The objective is an ``any`` over two ``report_manifest`` checks, one per budget
spelling (``maxUnavailable: 0``, ``minAvailable: 100%``). Each parses the
answer's fenced code blocks as YAML, so the selector and the budget come from
one document and a token in prose, a comment, a second document or another
``matchExpressions`` entry cannot stand in for either. The selector has to
take ``app: shop, version: green`` and not ``app: shop, version: blue``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from kube_agents_bench import transcript
from kube_agents_bench.verifiers import ReportManifestVerifier

TASK = Path(__file__).resolve().parent.parent / "tasks" / "compute-class-canary-active-migration-pdb-probe" / "task.yaml"
CHECK = "the-green-pdb-refuses-every-eviction"
TIMEOUT_SEC = 5.0

PDB_HEAD = "```yaml\napiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: shop-green-pdb\n"
DEPLOYMENT = (
    "---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: shop-green\n  labels:\n    app: shop\n"
    "    version: green\nspec:\n  strategy:\n    rollingUpdate:\n      maxUnavailable: 0\n  selector:\n"
    "    matchLabels:\n      app: shop\n      version: green\n"
)


@pytest.fixture(autouse=True)
def _clean_transcript():
    transcript.clear()
    yield
    transcript.clear()


def _matches(report: str) -> bool:
    doc = yaml.safe_load(TASK.read_text())
    (check,) = [c for c in doc["verification_spec"] if c.get("name") == CHECK]
    assert check["check"]["type"] == "any"
    transcript.set(report, [], final_message=report)
    return any(ReportManifestVerifier(**child).verify(TIMEOUT_SEC).success for child in check["check"]["checks"])


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


def test_matchexpressions_entries_are_read_one_at_a_time():
    # key: version from one entry and operator: In from another: the selector
    # leaves green evictable and freezes blue.
    trap = PDB_HEAD + (
        "spec:\n  maxUnavailable: 0\n  selector:\n    matchExpressions:\n    - key: app\n      operator: In\n"
        "      values: [shop]\n    - key: version\n      operator: NotIn\n      values: [green]\n```"
    )
    assert not _matches(trap)
    two_entries = PDB_HEAD + (
        "spec:\n  maxUnavailable: 0\n  selector:\n    matchExpressions:\n    - key: app\n      operator: In\n"
        "      values: [shop]\n    - key: version\n      operator: In\n      values: [green]\n```"
    )
    assert _matches(two_entries)


def test_a_selector_that_also_takes_blue_fails():
    for values in ("[blue, green]", "\n      - blue\n      - green"):
        report = PDB_HEAD + (
            "spec:\n  maxUnavailable: 0\n  selector:\n    matchExpressions:\n    - key: version\n"
            f"      operator: In\n      values: {values}\n```"
        )
        assert not _matches(report), values
    empty = PDB_HEAD + "spec:\n  maxUnavailable: 0\n  selector: {}\n```"
    assert not _matches(empty)


def test_a_line_ending_on_the_kind_does_not_open_a_document():
    fragment = "```yaml\nselector:\n  matchLabels:\n    app: shop\n    version: green\nmaxUnavailable: 0\n```"
    for lead in ("The resource you want is kind: PodDisruptionBudget\n", "### kind: PodDisruptionBudget\n"):
        assert not _matches(lead + fragment), lead


def test_comments_neither_refuse_nor_supply():
    commented = PDB_HEAD.replace("kind: PodDisruptionBudget", "kind: PodDisruptionBudget  # Stage 1 rollout guard") + (
        "spec:\n  maxUnavailable: 0\n  selector:\n    matchLabels:\n      app: shop\n      version: green\n```"
    )
    assert _matches(commented)
    from_comment = PDB_HEAD + (
        "spec:\n  maxUnavailable: 25%  # was maxUnavailable: 0 during the rollout\n  selector:\n    matchLabels:\n"
        "      app: shop\n      version: green\n```"
    )
    assert not _matches(from_comment)


def test_a_blank_line_json_kind_last_or_an_indented_fence_still_parses():
    blank_line = PDB_HEAD + (
        "\nspec:\n  maxUnavailable: 0\n\n  selector:\n    matchLabels:\n      app: shop\n      version: green\n```"
    )
    kind_last = (
        '```json\n{"spec": {"maxUnavailable": 0, "selector": {"matchLabels": {"app": "shop", "version": "green"}}},'
        ' "kind": "PodDisruptionBudget"}\n```'
    )
    in_a_list = "1. Apply this:\n\n   " + (
        PDB_HEAD + "spec:\n  maxUnavailable: 0\n  selector:\n    matchLabels:\n      app: shop\n      version: green\n```"
    ).replace("\n", "\n   ")
    for report in (blank_line, kind_last, in_a_list):
        assert _matches(report), report


def test_an_integer_min_available_is_not_accepted():
    report = PDB_HEAD + "spec:\n  minAvailable: 10\n  selector:\n    matchLabels:\n      app: shop\n      version: green\n```"
    assert not _matches(report)


def test_a_manifest_inside_a_relayed_fence_is_read():
    # The front door quotes the worker's result in a bare fence; the PDB's own
    # ```yaml block sits inside it.
    inner = PDB_HEAD + "spec:\n  maxUnavailable: 0\n  selector:\n    matchLabels:\n      app: shop\n      version: green\n```"
    relayed = "The worker's result:\n```\n## Rollout-Scoped PDB\n\nApply this:\n\n" + inner + "\n\n## Afterwards\n```"
    assert _matches(relayed)
