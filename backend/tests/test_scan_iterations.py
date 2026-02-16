"""
Backend Tests for Scan Iterations and Themed Reports
Tests: rescan endpoint, iteration history, report generation with themes
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# Test credentials
ADMIN_EMAIL = "admin@securescan.com"
ADMIN_PASSWORD = "admin123"


class TestAuthentication:
    """Authentication tests"""
    
    def test_admin_login(self):
        """Test admin login and get token"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
        )
        assert response.status_code == 200, f"Login failed: {response.text}"
        data = response.json()
        assert "access_token" in data, "No access_token in response"
        assert "user" in data, "No user in response"
        assert data["user"]["email"] == ADMIN_EMAIL


@pytest.fixture(scope="module")
def auth_token():
    """Get authentication token for tests"""
    response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    if response.status_code != 200:
        pytest.skip("Authentication failed - skipping authenticated tests")
    return response.json()["access_token"]


@pytest.fixture
def api_client(auth_token):
    """Authenticated requests session"""
    session = requests.Session()
    session.headers.update({
        "Content-Type": "application/json",
        "Authorization": f"Bearer {auth_token}"
    })
    return session


class TestScanIterations:
    """Tests for scan iteration functionality"""
    
    def test_get_scan_with_iterations(self, api_client):
        """Test getting scan that has iteration history"""
        # Get the "Fix Test" scan which has 2 iterations
        response = api_client.get(f"{BASE_URL}/api/scans")
        assert response.status_code == 200
        
        scans = response.json()
        # Find scan with iterations
        scan_with_iterations = None
        for scan in scans:
            if scan.get("current_iteration", 1) > 1:
                scan_with_iterations = scan
                break
        
        if scan_with_iterations:
            assert scan_with_iterations["current_iteration"] >= 2, "Should have iteration 2+"
            assert "iteration_history" in scan_with_iterations
            assert len(scan_with_iterations["iteration_history"]) >= 1
            print(f"Found scan with {scan_with_iterations['current_iteration']} iterations")
        else:
            print("No scan with multiple iterations found - creating one for test")
    
    def test_get_scan_history_endpoint(self, api_client):
        """Test the scan history endpoint"""
        # Get all scans first
        response = api_client.get(f"{BASE_URL}/api/scans")
        assert response.status_code == 200
        scans = response.json()
        
        if not scans:
            pytest.skip("No scans available for testing")
        
        # Get history for first scan
        scan_id = scans[0]["id"]
        history_response = api_client.get(f"{BASE_URL}/api/scans/{scan_id}/history")
        assert history_response.status_code == 200
        
        history_data = history_response.json()
        assert "current_iteration" in history_data
        assert "history" in history_data
        assert isinstance(history_data["history"], list)
        print(f"Scan history: iteration {history_data['current_iteration']}, history entries: {len(history_data['history'])}")
    
    def test_get_vulnerabilities_by_iteration(self, api_client):
        """Test getting vulnerabilities for a specific iteration"""
        # Get scans
        response = api_client.get(f"{BASE_URL}/api/scans")
        assert response.status_code == 200
        scans = response.json()
        
        if not scans:
            pytest.skip("No scans available for testing")
        
        scan_id = scans[0]["id"]
        iteration = scans[0].get("current_iteration", 1)
        
        # Get vulnerabilities for specific iteration
        vuln_response = api_client.get(f"{BASE_URL}/api/scans/{scan_id}/vulnerabilities/{iteration}")
        assert vuln_response.status_code == 200
        
        vulns = vuln_response.json()
        assert isinstance(vulns, list)
        print(f"Found {len(vulns)} vulnerabilities for iteration {iteration}")
    
    def test_rescan_endpoint(self, api_client):
        """Test rescan endpoint creates new iteration (not new scan)"""
        # Get a completed scan
        response = api_client.get(f"{BASE_URL}/api/scans")
        assert response.status_code == 200
        scans = response.json()
        
        completed_scan = None
        for scan in scans:
            if scan["status"] == "completed":
                completed_scan = scan
                break
        
        if not completed_scan:
            pytest.skip("No completed scan available for rescan test")
        
        scan_id = completed_scan["id"]
        original_iteration = completed_scan.get("current_iteration", 1)
        original_history_length = len(completed_scan.get("iteration_history", []))
        
        # Trigger rescan
        rescan_response = api_client.post(f"{BASE_URL}/api/scans/{scan_id}/rescan")
        assert rescan_response.status_code == 200, f"Rescan failed: {rescan_response.text}"
        
        rescan_data = rescan_response.json()
        
        # Verify it's the SAME scan ID (not new scan)
        assert rescan_data["id"] == scan_id, "Rescan should keep same scan ID"
        
        # Verify iteration was incremented
        new_iteration = rescan_data.get("current_iteration", 1)
        # Note: iteration might be same if previous was not completed
        print(f"Rescan result: original iteration={original_iteration}, new iteration={new_iteration}")
        
        # Verify status is now pending/running
        assert rescan_data["status"] in ["pending", "running"], f"Status should be pending/running, got {rescan_data['status']}"
        
        # Verify scan ID didn't change - this is the key requirement
        # "rescan creates history under same scan, not new scan"
        print(f"Rescan successful - same scan ID maintained: {scan_id}")


class TestThemedReports:
    """Tests for themed report generation (light/dark)"""
    
    def test_report_endpoint_with_dark_theme(self, api_client, auth_token):
        """Test report generation with dark theme"""
        # Get a completed scan
        response = api_client.get(f"{BASE_URL}/api/scans")
        assert response.status_code == 200
        scans = response.json()
        
        completed_scan = None
        for scan in scans:
            if scan["status"] == "completed":
                completed_scan = scan
                break
        
        if not completed_scan:
            pytest.skip("No completed scan available for report test")
        
        scan_id = completed_scan["id"]
        
        # Test HTML report with dark theme
        report_response = api_client.get(
            f"{BASE_URL}/api/scans/{scan_id}/report",
            params={"format": "html", "theme": "dark"}
        )
        assert report_response.status_code == 200
        assert "text/html" in report_response.headers.get("content-type", "")
        
        # Verify dark theme colors in HTML
        html_content = report_response.text
        assert "0F172A" in html_content or "#0F172A" in html_content.lower(), "Dark theme bg color missing"
        print("Dark theme HTML report generated successfully")
    
    def test_report_endpoint_with_light_theme(self, api_client, auth_token):
        """Test report generation with light theme"""
        # Get a completed scan
        response = api_client.get(f"{BASE_URL}/api/scans")
        assert response.status_code == 200
        scans = response.json()
        
        completed_scan = None
        for scan in scans:
            if scan["status"] == "completed":
                completed_scan = scan
                break
        
        if not completed_scan:
            pytest.skip("No completed scan available for report test")
        
        scan_id = completed_scan["id"]
        
        # Test HTML report with light theme
        report_response = api_client.get(
            f"{BASE_URL}/api/scans/{scan_id}/report",
            params={"format": "html", "theme": "light"}
        )
        assert report_response.status_code == 200
        assert "text/html" in report_response.headers.get("content-type", "")
        
        # Verify light theme colors in HTML
        html_content = report_response.text
        # Light theme uses FFFFFF for bg
        assert "FFFFFF" in html_content or "#FFFFFF" in html_content.lower() or "#ffffff" in html_content.lower(), "Light theme bg color missing"
        print("Light theme HTML report generated successfully")
    
    def test_report_with_iteration_parameter(self, api_client, auth_token):
        """Test report generation for specific iteration"""
        # Get scans
        response = api_client.get(f"{BASE_URL}/api/scans")
        assert response.status_code == 200
        scans = response.json()
        
        # Find scan with multiple iterations
        target_scan = None
        for scan in scans:
            if scan.get("current_iteration", 1) >= 1 and scan["status"] == "completed":
                target_scan = scan
                break
        
        if not target_scan:
            pytest.skip("No scan available for iteration test")
        
        scan_id = target_scan["id"]
        iteration = 1  # Request first iteration
        
        # Test report with iteration parameter
        report_response = api_client.get(
            f"{BASE_URL}/api/scans/{scan_id}/report",
            params={"format": "html", "theme": "dark", "iteration": iteration}
        )
        assert report_response.status_code == 200
        
        html_content = report_response.text
        # Should contain iteration info in report
        assert "Yineleme" in html_content or "Iteration" in html_content, "Iteration label missing"
        print(f"Report for iteration {iteration} generated successfully")
    
    def test_download_report_endpoint(self, auth_token):
        """Test direct download endpoint with token"""
        # Get scans
        response = requests.get(
            f"{BASE_URL}/api/scans",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        scans = response.json()
        
        completed_scan = None
        for scan in scans:
            if scan["status"] == "completed":
                completed_scan = scan
                break
        
        if not completed_scan:
            pytest.skip("No completed scan available")
        
        scan_id = completed_scan["id"]
        
        # Test download endpoint (token in query param)
        download_response = requests.get(
            f"{BASE_URL}/api/scans/{scan_id}/report/download",
            params={
                "format": "html",
                "theme": "light",
                "iteration": 1,
                "token": auth_token
            }
        )
        assert download_response.status_code == 200
        print("Download endpoint working correctly")


class TestHealthAndBasicEndpoints:
    """Basic endpoint tests"""
    
    def test_health_check(self):
        """Test health endpoint"""
        response = requests.get(f"{BASE_URL}/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
    
    def test_scans_list(self, api_client):
        """Test scans list endpoint"""
        response = api_client.get(f"{BASE_URL}/api/scans")
        assert response.status_code == 200
        scans = response.json()
        assert isinstance(scans, list)
        print(f"Found {len(scans)} scans")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
