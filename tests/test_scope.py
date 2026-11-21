import pytest

from surfacewatch.core import Scope, ScopeError, TargetType, classify


def make(**kw) -> Scope:
    data = {
        "name": "t",
        "targets": {
            "networks": ["192.168.56.0/24"],
            "hosts": ["10.10.10.5"],
            "domains": [
                {"name": "lab.local", "include_subdomains": True},
                {"name": "only-root.com", "include_subdomains": False},
            ],
        },
        "exclude": ["192.168.56.1", "secret.lab.local"],
    }
    data.update(kw)
    return Scope.from_dict(data)


def fake_resolver(mapping):
    return lambda host: mapping.get(host, [])


# ------------------------------------------------------------ sınıflandırma
@pytest.mark.parametrize("t,kind", [
    ("10.0.0.1", TargetType.IP), ("::1", TargetType.IP),
    ("10.0.0.0/24", TargetType.NETWORK), ("example.com", TargetType.DOMAIN),
])
def test_classify(t, kind):
    assert classify(t) is kind


# ------------------------------------------------------------ IP / ağ
@pytest.mark.parametrize("target,allowed", [
    ("192.168.56.10", True),
    ("10.10.10.5", True),
    ("10.10.10.6", False),       # hosts sadece tek IP
    ("192.168.56.1", False),     # exclude
    ("8.8.8.8", False),
    ("192.168.56.0/28", False),  # exclude edilen .1 ile çakışıyor
    ("192.168.56.128/25", True),
    ("192.168.0.0/16", False),   # kapsamdan geniş
])
def test_ip_and_network(target, allowed):
    assert make().check(target).allowed is allowed


# ------------------------------------------------------------ domain
def test_passive_domain_rules():
    s = make()
    assert s.check("lab.local", active=False)
    assert s.check("web.lab.local", active=False)
    assert not s.check("secret.lab.local", active=False)       # exclude
    assert not s.check("x.secret.lab.local", active=False)     # exclude alt alanları da kapsar
    assert s.check("only-root.com", active=False)
    assert not s.check("www.only-root.com", active=False)      # include_subdomains: false
    assert not s.check("evil-lab.local", active=False)         # sonek hilesi
    assert not s.check("lab.local.evil.com", active=False)


def test_active_domain_requires_ip_in_scope():
    s = make()
    r = fake_resolver({"web.lab.local": ["192.168.56.20"],
                       "cdn.lab.local": ["104.16.1.1"],
                       "mixed.lab.local": ["192.168.56.21", "104.16.1.1"]})
    ok = s.check("web.lab.local", resolver=r)
    assert ok.allowed and ok.resolved == ("192.168.56.20",)
    assert not s.check("cdn.lab.local", resolver=r)
    assert not s.check("mixed.lab.local", resolver=r)  # bir IP bile dışarıdaysa red
    assert not s.check("nxdomain.lab.local", resolver=r)


def test_allow_unscoped_resolution():
    s = make(options={"allow_unscoped_resolution": True})
    assert s.check("cdn.lab.local", resolver=fake_resolver({"cdn.lab.local": ["104.16.1.1"]}))


def test_resolver_error_is_denied():
    def boom(host):
        raise OSError("no network")
    assert not make().check("web.lab.local", resolver=boom)


# ------------------------------------------------------------ doğrulama
@pytest.mark.parametrize("bad", [
    {"targets": {}},
    {"targets": {"networks": ["not-an-ip"]}},
    {"targets": {"networks": ["10.0.0.0/8"]}},            # çok geniş
    {"targets": {"domains": ["https://example.com"]}},
    {"targets": {"domains": [{"nope": 1}]}},
    [],
])
def test_invalid_scope(bad):
    with pytest.raises(ScopeError):
        Scope.from_dict(bad)


def test_wildcard_and_trailing_dot_normalized():
    s = Scope.from_dict({"targets": {"domains": ["*.Example.COM."]}})
    assert s.domains[0].name == "example.com"
    assert s.check("API.example.com.", active=False)


def test_max_rate_option():
    assert make().max_rate == 100
    assert make(options={"max_rate": 20}).max_rate == 20
    with pytest.raises(ScopeError):
        make(options={"max_rate": 100000})
