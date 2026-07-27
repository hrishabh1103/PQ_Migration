def test_bulk_register_api_servers(client):
    payload = {
        "name": "Team Gateway Cluster",
        "endpoints": [
            "https://api.mycompany.com",
            "https://auth.mycompany.com/v1",
            "10.0.0.25:443"
        ],
        "environment": "PRODUCTION",
        "run_immediate_scan": True
    }
    res = client.post("/api/v1/api-hub/bulk-register", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["registered_targets_count"] == 3
    assert data["initiated_scans_count"] == 3

def test_import_openapi_spec(client):
    openapi_content = {
        "openapi": "3.0.0",
        "info": {"title": "Sample API", "version": "1.0"},
        "servers": [
            {"url": "https://api.payments.com"},
            {"url": "https://api.users.com"}
        ]
    }
    files = {
        "file": ("openapi.json", json_bytes(openapi_content), "application/json")
    }
    res = client.post("/api/v1/api-hub/import-openapi?environment=PRODUCTION", files=files)
    assert res.status_code == 200
    assert res.json()["registered_targets_count"] == 2

def json_bytes(obj):
    import json
    return json.dumps(obj).encode("utf-8")
