from vulnscan import Finding


def test_finding_to_dict():
    f = Finding("Test", "HIGH", "http://x", "ev", "desc", "fix",
                payload="p", proof="pr")
    d = f.to_dict()
    assert d["name"] == "Test"
    assert d["severity"] == "HIGH"
    assert d["payload"] == "p"


def test_severity_order():
    # Plus le numero est petit, plus la severite est haute
    assert Finding.SEV_ORDER["CRITICAL"] < Finding.SEV_ORDER["HIGH"]
    assert Finding.SEV_ORDER["HIGH"] < Finding.SEV_ORDER["MEDIUM"]
    assert Finding.SEV_ORDER["MEDIUM"] < Finding.SEV_ORDER["LOW"]
    assert Finding.SEV_ORDER["LOW"] < Finding.SEV_ORDER["INFO"]
