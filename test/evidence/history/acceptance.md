# Release acceptance checklist

`acceptance-checklist.json` is the mandatory gate ledger. Its 25 traffic scenarios
come from `test/e2e/matrix/coverage.json`; four additional gates cover Linux 5.10,
final-source validation, artifact provenance and security review.

Run the offline guard:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test/e2e/matrix/release_acceptance.py
PYTHONDONTWRITEBYTECODE=1 python3 test/e2e/matrix/release_acceptance.py --require-ready
```

The second command must fail while any mandatory gate is OPEN or PARTIAL.
Scoped historical successes remain PARTIAL until their entire declared scope
has reviewed evidence. A PASSED record requires evidence references and an empty
remaining-work field. The guard checks ledger completeness and consistency;
**it does not authenticate evidence or replace human release review**.

The accepted-gate percentage is different from the earlier approximate 75%
engineering implementation estimate. Initially no full release gate is accepted:
that does not erase the documented successful component and scoped runtime tests.
Do not narrow required scope, delete gates, or convert unsupported combinations
into successes to manufacture 100%. Verify supported combinations and explicitly
test refusal of unsupported combinations.

No versioned release candidate should be prepared as release-ready before this
ledger and the final validation agree. Publication, production signing, tag push
and PR creation remain separately authorized actions.
