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
