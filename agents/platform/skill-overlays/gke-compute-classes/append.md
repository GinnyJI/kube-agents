<!-- kube-agents: local addition (auto-injected by sync-upstream-skills.py) -->

## Node upgrades during a PDB-guarded canary

The "Node auto-upgrades" row in `references/compute-class-lifecycle.md` overstates the protection:
GKE's node-upgrade drain respects a PodDisruptionBudget for up to one hour, then evicts the pods
anyway. A node auto-upgrade can therefore still evict the green pods of a multi-hour canary guarded
by a `maxUnavailable: 0` PDB. When the rollout must not be disrupted, run it outside the cluster's
maintenance window or add a maintenance exclusion for its duration (see `gke-upgrades`).

## Reading the code index from this install

`references/compute-class-code-index.md` opens by telling its reader to clone the repository, and
its "Code verification instructions" section runs `git log` and `git blame`. Those steps are for the
user's own terminal: this install cannot reach GitHub, so follow the CRITICAL RULE above and hand
them to the user. The index's `groupRulesByScore` entry names a function the upstream source does
not have; do not cite it.
