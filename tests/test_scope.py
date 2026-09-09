from sitesweep.scope import Scope

def test_scope():
    s=Scope(['example.com','*.example.org'])
    assert s.allows_host('example.com')
    assert s.allows_host('api.example.org')
    assert not s.allows_host('evil-example.org')
