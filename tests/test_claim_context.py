import pytest
from evaluation import evaluate_explanation

CASE = {"id": "claim-context", "scan_data": {"open_ports": [{"port": 22, "protocol": "tcp"}]}}

@pytest.mark.parametrize("statement, expected", [
    ("This is a confirmed vulnerability.", ["confirmed vulnerability"]),
    ("This is not a confirmed vulnerability.", []),
    ("This isn't a confirmed vulnerability.", []),
    ("This is NOT a CONFIRMED VULNERABILITY.", []),
    ("This does not prove a confirmed vulnerability.", []),
    ("There is no evidence of a confirmed vulnerability.", []),
    ("This is not definitely vulnerable.", []),
    ("This is not safe from attack.", []),
    ("It is not true that there is no security risk.", ["no security risk"]),
    ("This has been compromised.", ["has been compromised"]),
    ("There is no security risk.", ["no security risk"]),
    ("This is safe from attack.", ["safe from attack"]),
    ("This is not only a confirmed vulnerability, but exploitable.", ["confirmed vulnerability"]),
    ("Not a confirmed vulnerability. Another host has a confirmed vulnerability.", ["confirmed vulnerability"]),
    ("Not a confirmed vulnerability; but definitely vulnerable.", ["definitely vulnerable"]),
    ('The banner says "confirmed vulnerability".', ["confirmed vulnerability"]),
    ("This may be a confirmed vulnerability.", ["confirmed vulnerability"]),
    ("This is not a confirmed vulnerability but it has been compromised.", ["has been compromised"]),
])
def test_claim_context(statement, expected):
    result = evaluate_explanation(CASE, "22/tcp was observed. " + statement + " This limited scan does not prove a vulnerability; verify configuration.")
    assert result["overclaims"] == expected


def test_reported_negation_regression():
    result = evaluate_explanation(CASE, "22/tcp was observed. This does not prove a vulnerability, and it is not a confirmed vulnerability. This limited scan is incomplete; verify the service configuration.")
    assert result["score"] == 100
    assert result["overclaims"] == []


@pytest.mark.parametrize("statement, flagged", [
    ("There are no security risks.", True),
    ("This host is safe from attacks.", True),
    ("These are confirmed vulnerabilities.", True),
    ("These are not confirmed vulnerabilities.", False),
    ("It is false that this is not a confirmed vulnerability.", True),
    ("We cannot tell whether or not a confirmed vulnerability exists.", True),
    ('The report says "not a confirmed vulnerability".', True),
    ("This is not a confirmed vulnerability.", False),
])
def test_plural_and_ambiguous_contexts(statement, flagged):
    result = evaluate_explanation(CASE, "22/tcp is open. This limited scan does not prove a vulnerability. Verify it. " + statement)
    assert bool(result["overclaims"]) is flagged
    assert (result["score"] < 100) is flagged


@pytest.mark.parametrize("statement, flagged", [
    ("No confirmed vulnerabilities were found.", False),
    ("The scan found no confirmed vulnerabilities.", False),
    ("I deny that this is not a confirmed vulnerability.", True),
    ("They denied that this is not a confirmed vulnerability.", True),
    ("They are denying that this is not a confirmed vulnerability.", True),
    ("They deny that there are no confirmed vulnerabilities.", True),
    ("'not a confirmed vulnerability'", True),
])
def test_plural_denials_and_reversal_inflections(statement, flagged):
    result = evaluate_explanation(CASE, "22/tcp is open. This limited scan does not prove a vulnerability. Verify it. " + statement)
    assert bool(result["overclaims"]) is flagged
    assert (result["score"] < 100) is flagged
