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
