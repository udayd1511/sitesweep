from sitesweep.checks.secrets import scan_text

def test_aws():
    rules=[{'id':'aws','regex':'AKIA[0-9A-Z]{16}','severity':'high'}]
    assert scan_text('AKIA1234567890ABCDEF',rules)
