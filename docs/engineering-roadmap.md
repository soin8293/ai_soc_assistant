# Network explanations and evaluation

## Current engineering work

Run the offline fixture suite and examine false positives and false negatives per dimension. Preserve held-out examples of singular/plural claims, direct denial, quoted denial, uncertainty and reversed negation. Known ambiguous contexts remain conservative review flags; the rules do not parse arbitrary language.

## Next operational acceptance

A versioned authorized input contract, repeated operator review and an independently recorded error rate on a defined held-out set. No live scan or model call is required by the offline tests.

Implementation, automated checks and synthetic drills establish bounded behavior.
An operational record must separately identify the problem, requirements, exact
version/environment, deployment, upgrade/rollback, repeated use and measured outcome.
Those lifecycle fields are pending until actual use supplies evidence.

## Change and recovery

Extend this project before creating another repository for a related capability.
Add cloud hosting, infrastructure as code or monitoring only for a demonstrated
workload requirement. Preserve the previous version and configuration; reproduce
failures in a disposable environment, revert the scoped change if acceptance fails,
and record any lost in-memory state or required operator recovery. Never test
cleanup against personal data or publish raw host, customer or session records.
