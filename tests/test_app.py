import asyncio

import pytest
from fastapi.testclient import TestClient

import main


class FakeHost:
    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, protocol):
        assert protocol == "tcp"
        return {
            22: {"state": "open", "name": "ssh"},
            80: {"state": "closed", "name": "http"},
        }


class FakeScanner:
    def scan(self, hosts, arguments):
        assert hosts == "127.0.0.1"
        assert "--top-ports 100" in arguments

    def __getitem__(self, target):
        assert target == "127.0.0.1"
        return FakeHost()


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.50.4", "::1", "fd00::1"],
)
def test_validate_target_accepts_bounded_ranges(target):
    assert main.validate_target(target)


@pytest.mark.parametrize("target", ["8.8.8.8", "example.com", "169.254.1.1", "2001:4860:4860::8888"])
def test_validate_target_rejects_public_hostnames_and_link_local(target):
    with pytest.raises(ValueError):
        main.validate_target(target)


def test_scan_normalizes_only_open_ports():
    result = main.perform_port_scan("127.0.0.1", FakeScanner())
    assert result["scan_profile"] == "top-100-ports"
    assert result["open_ports"] == [
        {"port": 22, "protocol": "tcp", "service": "ssh"}
    ]


def test_local_fallback_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = asyncio.run(
        main.explain_scan(
            {
                "target": "127.0.0.1",
                "scan_profile": "top-100-ports",
                "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}],
            }
        )
    )
    assert result["source"] == "local-rules"
    assert "not a vulnerability assessment" in result["data"]


def test_endpoint_requires_authorization():
    response = TestClient(main.app).post(
        "/scan", json={"target": "127.0.0.1", "authorized": False}
    )
    assert response.status_code == 400


def test_endpoint_rejects_public_target_before_scanning():
    response = TestClient(main.app).post(
        "/scan", json={"target": "8.8.8.8", "authorized": True}
    )
    assert response.status_code == 400
