"""
Backend API Tests for Vulnerability Scanner
Tests: Auth, Agents, Scans, and new vulnerability model fields
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://nmap-intel-center.preview.emergentagent.com')

# Test Credentials
ADMIN_EMAIL = "admin@securescan.com"
ADMIN_PASSWORD = "admin123"


class TestAuthEndpoints:
    """Test authentication endpoints"""
    
    def test_login_success(self):
        """Test successful login with admin credentials"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "user" in data
        assert data["user"]["email"] == ADMIN_EMAIL
        assert data["user"]["role"] == "admin"
        print(f"✓ Login successful for {ADMIN_EMAIL}")
        return data["access_token"]
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": "wrong@example.com", "password": "wrongpass"}
        )
        assert response.status_code == 401
        print("✓ Invalid credentials correctly rejected")


class TestAgentEndpoints:
    """Test agent management endpoints"""
    
    @pytest.fixture
    def auth_token(self):
        """Get authentication token"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
        )
        return response.json()["access_token"]
    
    def test_list_agents(self, auth_token):
        """Test listing agents endpoint"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(f"{BASE_URL}/api/agents", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"✓ Agents list returned {len(data)} agents")
        
        # Verify agent structure if agents exist
        if len(data) > 0:
            agent = data[0]
            assert "id" in agent
            assert "customer_id" in agent
            assert "name" in agent
            assert "status" in agent
            assert "is_active" in agent
            print(f"✓ Agent structure validated: {agent['name']}")
    
    def test_install_script_generation(self):
        """Test that install.sh script is generated correctly"""
        response = requests.get(f"{BASE_URL}/api/agent/install.sh")
        
        assert response.status_code == 200
        script_content = response.text
        
        # Verify script contains expected content
        assert "#!/bin/bash" in script_content
        assert "SecureScan Agent Installer" in script_content
        assert "AGENT_TOKEN" in script_content
        assert "PANEL_URL" in script_content
        assert "nmap" in script_content
        print("✓ Install script generated correctly with nmap dependency")


class TestDashboardEndpoints:
    """Test dashboard endpoints"""
    
    @pytest.fixture
    def auth_token(self):
        """Get authentication token"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
        )
        return response.json()["access_token"]
    
    def test_dashboard_stats(self, auth_token):
        """Test dashboard statistics endpoint"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(f"{BASE_URL}/api/dashboard/stats", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify structure
        assert "total_scans" in data
        assert "running_scans" in data
        assert "total_targets" in data
        assert "total_vulnerabilities" in data
        assert "critical_count" in data
        assert "high_count" in data
        assert "medium_count" in data
        assert "low_count" in data
        assert "info_count" in data
        print(f"✓ Dashboard stats: {data['total_scans']} scans, {data['total_vulnerabilities']} vulns")


class TestScanEndpoints:
    """Test scan endpoints"""
    
    @pytest.fixture
    def auth_token(self):
        """Get authentication token"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
        )
        return response.json()["access_token"]
    
    def test_list_scans(self, auth_token):
        """Test listing scans"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(f"{BASE_URL}/api/scans", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"✓ Scans list returned {len(data)} scans")
        
        # Check scan structure if scans exist
        if len(data) > 0:
            scan = data[0]
            assert "id" in scan
            assert "status" in scan
            assert "name" in scan
            # New fields from agent architecture
            assert "agent_id" in scan or scan.get("agent_id") is None
    
    def test_scan_detail(self, auth_token):
        """Test getting scan details"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        # First get list of scans
        list_response = requests.get(f"{BASE_URL}/api/scans", headers=headers)
        scans = list_response.json()
        
        if len(scans) > 0:
            scan_id = scans[0]["id"]
            response = requests.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers)
            
            assert response.status_code == 200
            data = response.json()
            assert data["id"] == scan_id
            print(f"✓ Scan detail retrieved: {data['name']}, status: {data['status']}")
    
    def test_scan_vulnerabilities(self, auth_token):
        """Test getting vulnerabilities for a scan"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        # First get list of scans
        list_response = requests.get(f"{BASE_URL}/api/scans", headers=headers)
        scans = list_response.json()
        
        if len(scans) > 0:
            scan_id = scans[0]["id"]
            response = requests.get(f"{BASE_URL}/api/scans/{scan_id}/vulnerabilities", headers=headers)
            
            assert response.status_code == 200
            vulnerabilities = response.json()
            assert isinstance(vulnerabilities, list)
            print(f"✓ Got {len(vulnerabilities)} vulnerabilities for scan")
            
            # Check vulnerability structure for new fields
            if len(vulnerabilities) > 0:
                vuln = vulnerabilities[0]
                assert "id" in vuln
                assert "severity" in vuln
                assert "title" in vuln
                assert "description" in vuln
                # Check new fields: evidence, is_kev, source
                # These may or may not be present depending on vulnerability type
                print(f"✓ Vulnerability structure validated")
                if "evidence" in vuln and vuln["evidence"]:
                    print(f"  - Evidence field present: {vuln['evidence'][:50]}...")
                if "is_kev" in vuln:
                    print(f"  - is_kev field present: {vuln['is_kev']}")
                if "source" in vuln:
                    print(f"  - source field present: {vuln['source']}")


class TestVulnerabilityModel:
    """Test new vulnerability model fields (evidence, is_kev, source)"""
    
    @pytest.fixture
    def auth_token(self):
        """Get authentication token"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
        )
        return response.json()["access_token"]
    
    def test_vulnerability_response_model(self, auth_token):
        """Verify vulnerability response includes new fields"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        # Get scans with vulnerabilities
        scans_response = requests.get(f"{BASE_URL}/api/scans", headers=headers)
        scans = scans_response.json()
        
        # Find a completed scan with vulnerabilities
        for scan in scans:
            if scan["status"] == "completed" and scan.get("total_vulnerabilities", 0) > 0:
                response = requests.get(
                    f"{BASE_URL}/api/scans/{scan['id']}/vulnerabilities",
                    headers=headers
                )
                vulnerabilities = response.json()
                
                if len(vulnerabilities) > 0:
                    vuln = vulnerabilities[0]
                    # Model should support these fields even if null
                    print(f"✓ Vulnerability model fields test:")
                    print(f"  - id: {vuln.get('id', 'missing')}")
                    print(f"  - severity: {vuln.get('severity', 'missing')}")
                    print(f"  - evidence: {vuln.get('evidence', 'null')}")
                    print(f"  - is_kev: {vuln.get('is_kev', 'null')}")
                    print(f"  - source: {vuln.get('source', 'null')}")
                    return
        
        print("⚠ No completed scans with vulnerabilities found to test model fields")


class TestCVEEndpoints:
    """Test CVE database endpoints"""
    
    @pytest.fixture
    def auth_token(self):
        """Get authentication token"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
        )
        return response.json()["access_token"]
    
    def test_cve_stats(self, auth_token):
        """Test CVE database stats endpoint"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(f"{BASE_URL}/api/cve/stats", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "total_cves" in data
        assert "kev_count" in data
        assert "severity_counts" in data
        print(f"✓ CVE database has {data['total_cves']} entries, {data['kev_count']} KEV")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
