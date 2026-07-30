def test_api_health(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_api_targets_crud(client):
    # Create target
    payload = {
        "name": "Production Gateway",
        "target_type": "HOSTNAME",
        "target_value": "demo.internal",
        "is_authorized": True,
        "environment": "PRODUCTION"
    }
    res = client.post("/api/v1/targets", json=payload)
    assert res.status_code == 201
    target_data = res.json()
    assert target_data["name"] == "Production Gateway"
    target_id = target_data["id"]

    # Get target
    res_get = client.get(f"/api/v1/targets/{target_id}")
    assert res_get.status_code == 200

    # List targets
    res_list = client.get("/api/v1/targets")
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1

def test_api_scan_workflow(client):
    # 1. Register target
    t_res = client.post("/api/v1/targets", json={
        "name": "Demo System",
        "target_type": "HOSTNAME",
        "target_value": "demo.internal",
        "is_authorized": True,
        "environment": "DEVELOPMENT"
    })
    target_id = t_res.json()["id"]

    # 2. Trigger scan
    s_res = client.post("/api/v1/scans", json={
        "target_id": target_id,
        "requested_scanners": ["mock-scanner"]
    })
    assert s_res.status_code == 201
    scan_id = s_res.json()["id"]

    # 3. Get scan job
    s_get = client.get(f"/api/v1/scans/{scan_id}")
    assert s_get.status_code == 200

    # 4. Check assets list
    a_res = client.get("/api/v1/assets")
    assert a_res.status_code == 200

    # 5. Check findings list
    f_res = client.get("/api/v1/findings")
    assert f_res.status_code == 200

    # 6. Check dashboard stats
    st_res = client.get("/api/v1/stats/dashboard")
    assert st_res.status_code == 200
    stats = st_res.json()
    assert "algorithm_distribution" in stats

def test_api_clear_and_archive_scan_history(client):
    # 1. Create target & scan
    t_res = client.post("/api/v1/targets", json={
        "name": "Archive Test Target",
        "target_type": "URL",
        "target_value": "http://archive.test",
        "is_authorized": True,
        "environment": "DEVELOPMENT"
    })
    target_id = t_res.json()["id"]

    s_res = client.post("/api/v1/scans", json={
        "target_id": target_id,
        "requested_scanners": ["mock-scanner"]
    })
    scan_id = s_res.json()["id"]

    # 2. Export archive
    arch_res = client.get("/api/v1/scans/export/archive")
    assert arch_res.status_code == 200
    assert arch_res.headers["content-type"].startswith("application/json")
    arch_json = arch_res.json()
    assert "total_scans" in arch_json
    assert arch_json["total_scans"] >= 1

    # 3. Delete single scan
    del_single = client.delete(f"/api/v1/scans/{scan_id}")
    assert del_single.status_code == 200

    # 4. Clear all scans
    clear_all = client.delete("/api/v1/scans")
    assert clear_all.status_code == 200
    assert clear_all.json()["deleted_scans"] >= 0

