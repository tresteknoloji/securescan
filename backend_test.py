#!/usr/bin/env python3
"""
Vulnerability Scanner Backend API Tests
Tests all API endpoints for the vulnerability scanner application
"""

import requests
import sys
import json
from datetime import datetime

class VulnScannerAPITester:
    def __init__(self, base_url="https://threat-detect-23.preview.emergentagent.com"):
        self.base_url = base_url
        self.token = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name}")
        else:
            print(f"❌ {name} - {details}")
        
        self.test_results.append({
            "test": name,
            "success": success,
            "details": details
        })

    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Run a single API test"""
        url = f"{self.base_url}/api/{endpoint}"
        test_headers = {'Content-Type': 'application/json'}
        
        if self.token:
            test_headers['Authorization'] = f'Bearer {self.token}'
        
        if headers:
            test_headers.update(headers)

        try:
            if method == 'GET':
                response = requests.get(url, headers=test_headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=test_headers, timeout=30)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=test_headers, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(url, headers=test_headers, timeout=30)

            success = response.status_code == expected_status
            details = f"Status: {response.status_code}"
            
            if not success:
                details += f" (Expected {expected_status})"
                try:
                    error_data = response.json()
                    if 'detail' in error_data:
                        details += f" - {error_data['detail']}"
                except:
                    details += f" - {response.text[:100]}"

            self.log_test(name, success, details)
            
            if success:
                try:
                    return response.json()
                except:
                    return {}
            return {}

        except Exception as e:
            self.log_test(name, False, f"Error: {str(e)}")
            return {}

    def test_health_check(self):
        """Test health check endpoint"""
        return self.run_test("Health Check", "GET", "health", 200)

    def test_login(self):
        """Test login with admin credentials"""
        login_data = {
            "email": "admin@securescan.com",
            "password": "admin123"
        }
        
        response = self.run_test("Admin Login", "POST", "auth/login", 200, login_data)
        
        if response and 'access_token' in response:
            self.token = response['access_token']
            self.log_test("Token Retrieved", True, "JWT token obtained")
            return True
        else:
            self.log_test("Token Retrieved", False, "No access token in response")
            return False

    def test_get_me(self):
        """Test get current user info"""
        return self.run_test("Get Current User", "GET", "auth/me", 200)

    def test_dashboard_stats(self):
        """Test dashboard statistics"""
        return self.run_test("Dashboard Stats", "GET", "dashboard/stats", 200)

    def test_get_targets(self):
        """Test get targets"""
        return self.run_test("Get Targets", "GET", "targets", 200)

    def test_create_target(self):
        """Test create target"""
        target_data = {
            "name": f"Test Target {datetime.now().strftime('%H%M%S')}",
            "target_type": "ip",
            "value": "192.168.1.100",
            "description": "Test target for API testing"
        }
        
        response = self.run_test("Create Target", "POST", "targets", 200, target_data)
        return response.get('id') if response else None

    def test_get_scans(self):
        """Test get scans"""
        return self.run_test("Get Scans", "GET", "scans", 200)

    def test_create_scan(self, target_id):
        """Test create scan"""
        if not target_id:
            self.log_test("Create Scan", False, "No target ID available")
            return None
            
        scan_data = {
            "name": f"Test Scan {datetime.now().strftime('%H%M%S')}",
            "target_ids": [target_id],
            "config": {
                "scan_type": "quick",
                "port_range": "1-100",
                "check_ssl": True,
                "check_cve": True,
                "pci_compliance": True
            }
        }
        
        response = self.run_test("Create Scan", "POST", "scans", 200, scan_data)
        return response.get('id') if response else None

    def test_get_scan_detail(self, scan_id):
        """Test get scan detail"""
        if not scan_id:
            self.log_test("Get Scan Detail", False, "No scan ID available")
            return
            
        return self.run_test("Get Scan Detail", "GET", f"scans/{scan_id}", 200)

    def test_get_users(self):
        """Test get users (admin only)"""
        return self.run_test("Get Users", "GET", "users", 200)

    def test_get_translations(self):
        """Test get translations"""
        return self.run_test("Get Translations (EN)", "GET", "translations/en", 200)

    def test_get_translations_tr(self):
        """Test get Turkish translations"""
        return self.run_test("Get Translations (TR)", "GET", "translations/tr", 200)

    def test_cve_status(self):
        """Test CVE database status"""
        return self.run_test("CVE Status", "GET", "cve/status", 200)

    def test_settings_branding(self):
        """Test get branding settings"""
        return self.run_test("Get Branding Settings", "GET", "settings/branding", 200)

    def test_settings_smtp(self):
        """Test get SMTP settings"""
        return self.run_test("Get SMTP Settings", "GET", "settings/smtp", 200)

    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting Vulnerability Scanner API Tests")
        print(f"📡 Testing against: {self.base_url}")
        print("=" * 60)

        # Basic health check
        self.test_health_check()

        # Authentication tests
        if not self.test_login():
            print("❌ Login failed - stopping tests")
            return False

        self.test_get_me()

        # Core functionality tests
        self.test_dashboard_stats()
        self.test_get_targets()
        
        # Create a test target
        target_id = self.test_create_target()
        
        # Scan tests
        self.test_get_scans()
        scan_id = self.test_create_scan(target_id)
        
        if scan_id:
            self.test_get_scan_detail(scan_id)

        # User management (admin only)
        self.test_get_users()

        # Settings tests
        self.test_settings_branding()
        self.test_settings_smtp()

        # Translation tests
        self.test_get_translations()
        self.test_get_translations_tr()

        # CVE tests
        self.test_cve_status()

        return True

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {self.tests_run}")
        print(f"Passed: {self.tests_passed}")
        print(f"Failed: {self.tests_run - self.tests_passed}")
        print(f"Success Rate: {(self.tests_passed/self.tests_run*100):.1f}%")
        
        if self.tests_passed < self.tests_run:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  • {result['test']}: {result['details']}")

        return self.tests_passed == self.tests_run

def main():
    """Main test function"""
    tester = VulnScannerAPITester()
    
    try:
        success = tester.run_all_tests()
        tester.print_summary()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n⚠️  Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n💥 Unexpected error: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())