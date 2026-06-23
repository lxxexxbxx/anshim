"""FastAPI 엔드포인트 테스트."""

import pytest
from fastapi.testclient import TestClient

from anshim.core.api.server import app
from anshim.core.db.database import reset_engine


@pytest.fixture(autouse=True)
def reset_db(tmp_path, monkeypatch):
    """각 테스트마다 임시 DB 사용."""
    db_path = tmp_path / "test_api.db"
    reset_engine()

    # DB 경로 패치
    import anshim.core.db.database as db_mod
    import anshim.core.db.repository as repo_mod

    monkeypatch.setattr(db_mod, "DEFAULT_DB_PATH", db_path)

    # repository 모듈의 ScanRepository/VulnerabilityRepository를 패치하여
    # 임시 DB 경로를 사용하도록 함
    original_scan_repo = repo_mod.ScanRepository

    class PatchedScanRepo(original_scan_repo):
        def __init__(self):
            super().__init__(db_path=db_path)

    original_vuln_repo = repo_mod.VulnerabilityRepository

    class PatchedVulnRepo(original_vuln_repo):
        def __init__(self):
            super().__init__(db_path=db_path)

    monkeypatch.setattr(
        "anshim.core.api.server.ScanRepository",
        PatchedScanRepo,
    )
    monkeypatch.setattr(
        "anshim.core.api.server.VulnerabilityRepository",
        PatchedVulnRepo,
    )

    yield db_path
    reset_engine()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


class TestHealthEndpoint:
    def test_health_ok(self, client):
        res = client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["service"] == "anshim-api"


class TestScanListEndpoint:
    def test_list_scans_empty(self, client):
        res = client.get("/api/scans")
        assert res.status_code == 200
        data = res.json()
        assert "items" in data
        assert "total" in data
        assert data["total"] == 0
        assert data["items"] == []

    def test_list_scans_pagination_params(self, client):
        res = client.get("/api/scans?limit=5&offset=0")
        assert res.status_code == 200

    def test_list_scans_invalid_limit(self, client):
        res = client.get("/api/scans?limit=0")
        assert res.status_code == 422

    def test_list_scans_returns_scan_after_create(self, client, reset_db):
        from anshim.core.db.repository import ScanRepository

        repo = ScanRepository(db_path=reset_db)
        repo.create_scan(target_path="/tmp/test", compliance_types=["isms-p"])

        res = client.get("/api/scans")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["target_path"] == "/tmp/test"


class TestScanDetailEndpoint:
    def test_get_scan_not_found(self, client):
        res = client.get("/api/scans/nonexistent-id")
        assert res.status_code == 404

    def test_get_scan_ok(self, client, reset_db):
        from anshim.core.db.repository import ScanRepository

        repo = ScanRepository(db_path=reset_db)
        scan = repo.create_scan(target_path="/tmp/myproject", compliance_types=["isms"])

        res = client.get(f"/api/scans/{scan.id}")
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == scan.id
        assert data["target_path"] == "/tmp/myproject"
        assert data["status"] == "running"


class TestVulnerabilityEndpoint:
    def test_list_vulnerabilities_empty(self, client, reset_db):
        from anshim.core.db.repository import ScanRepository

        repo = ScanRepository(db_path=reset_db)
        scan = repo.create_scan(target_path="/tmp/test")

        res = client.get(f"/api/scans/{scan.id}/vulnerabilities")
        assert res.status_code == 200
        assert res.json() == []

    def test_list_vulnerabilities_scan_not_found(self, client):
        res = client.get("/api/scans/bad-id-xxx/vulnerabilities")
        assert res.status_code == 404


class TestStatsEndpoint:
    def test_stats_empty(self, client):
        res = client.get("/api/stats")
        assert res.status_code == 200
        data = res.json()
        assert "total_scans" in data
        assert "total_vulnerabilities" in data
        assert "severity_distribution" in data
        assert "recent_scans" in data
        assert data["total_scans"] == 0
        assert data["total_vulnerabilities"] == 0

    def test_stats_severity_keys(self, client):
        res = client.get("/api/stats")
        assert res.status_code == 200
        sev = res.json()["severity_distribution"]
        for key in ("critical", "high", "medium", "low", "info"):
            assert key in sev

    def test_stats_counts_scans(self, client, reset_db):
        from anshim.core.db.repository import ScanRepository

        repo = ScanRepository(db_path=reset_db)
        repo.create_scan(target_path="/tmp/a")
        repo.create_scan(target_path="/tmp/b")

        res = client.get("/api/stats")
        assert res.status_code == 200
        assert res.json()["total_scans"] == 2


class TestDeleteScanEndpoint:
    def test_delete_scan_not_found(self, client):
        res = client.delete("/api/scans/does-not-exist")
        assert res.status_code == 404

    def test_delete_scan_ok(self, client, reset_db):
        from anshim.core.db.repository import ScanRepository

        repo = ScanRepository(db_path=reset_db)
        scan = repo.create_scan(target_path="/tmp/del")

        res = client.delete(f"/api/scans/{scan.id}")
        assert res.status_code == 200
        assert "삭제" in res.json()["message"]

        res2 = client.get(f"/api/scans/{scan.id}")
        assert res2.status_code == 404
