"""A workflow with both a push `paths:` list and a `dorny/paths-filter` step keeps the two equal.

Such a workflow is a required check: on a pull request and in the merge queue
it always starts and the filter step decides whether to test; on a push to
`main` the `paths:` list decides instead. `main-broken-notify.yml` reads that
push history and closes a `ci:main-broken` issue on the first green run. A path
in `paths:` but not in the filter starts a push run whose filter reports
`false`, skips every test step and concludes `success`, so the notifier closes
the issue and names a commit that fixed nothing. The headers ask for the lists
to match by hand; this holds them to it.
"""

import unittest

import yaml

from tests.test_workflow_pins_and_fork_guards import WORKFLOWS_DIR, _load, _workflow_files

_PATHS_FILTER = "dorny/paths-filter@"
_PUSH = "push"
# a2a-test.yml, k8s-operator-test.yml and k8sapiproxy-test.yml; a sweep that found fewer saw
# too little.
_PAIRED_WORKFLOWS_FLOOR = 3


def _on(doc: dict):
    # PyYAML reads an unquoted `on:` key as the boolean True (YAML 1.1).
    return doc.get("on", doc.get(True))


def _paired_workflows():
    """(workflow file name, push paths, filter steps) for every workflow with both."""
    found = []
    for path in _workflow_files(WORKFLOWS_DIR):
        _text, doc = _load(path)
        if doc is None:
            continue
        on = _on(doc)
        push = on.get(_PUSH) if isinstance(on, dict) else None
        paths = push.get("paths") if isinstance(push, dict) else None
        if not paths:
            continue
        steps = [
            step
            for job in (doc.get("jobs") or {}).values()
            for step in (job or {}).get("steps") or []
            if str(step.get("uses", "")).startswith(_PATHS_FILTER)
        ]
        if steps:
            found.append((path.name, paths, steps))
    return found


class PushPathsMatchChangeFilterTest(unittest.TestCase):
    def test_the_sweep_saw_the_paired_workflows(self) -> None:
        self.assertGreaterEqual(len(_paired_workflows()), _PAIRED_WORKFLOWS_FLOOR)

    def test_push_paths_equal_the_change_filter(self) -> None:
        for name, paths, steps in _paired_workflows():
            with self.subTest(workflow=name):
                self.assertEqual(1, len(steps), f"{name}: expected one paths-filter step")
                filters = yaml.safe_load((steps[0].get("with") or {}).get("filters") or "")
                self.assertIsInstance(filters, dict, f"{name}: `filters` is not a mapping")
                self.assertEqual(1, len(filters), f"{name}: expected one filter: {sorted(filters)}")
                (filter_paths,) = filters.values()
                self.assertEqual(
                    sorted(paths),
                    sorted(filter_paths),
                    f"{name}: the push `paths:` list and the paths-filter list differ; a push "
                    "touching a path only `paths:` names tests nothing and reports success",
                )


if __name__ == "__main__":
    unittest.main()
