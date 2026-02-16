"""
CVE Database Manager
Full NVD sync + CISA KEV integration + Incremental updates
"""
import asyncio
import httpx
import gzip
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, AsyncGenerator
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# NVD API Configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 2000

# CISA KEV API
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# CPE Dictionary API
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


class CVEManager:
    """Manages CVE database synchronization from multiple sources"""
    
    def __init__(self, db, nvd_api_key: Optional[str] = None):
        self.db = db
        self.nvd_api_key = nvd_api_key
        self._sync_status = {
            "is_running": False,
            "current_source": None,
            "progress": 0,
            "total": 0,
            "synced": 0,
            "errors": [],
            "started_at": None,
            "last_update": None
        }
    
    @property
    def sync_status(self) -> dict:
        return self._sync_status.copy()
    
    async def get_database_stats(self) -> dict:
        """Get CVE database statistics"""
        total_cves = await self.db.cves.count_documents({})
        kev_count = await self.db.cves.count_documents({"is_kev": True})
        
        # Count by severity
        severity_pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
        ]
        severity_stats = await self.db.cves.aggregate(severity_pipeline).to_list(10)
        severity_counts = {s["_id"]: s["count"] for s in severity_stats if s["_id"]}
        
        # Get year distribution
        year_pipeline = [
            {"$project": {"year": {"$substr": ["$cve_id", 4, 4]}}},
            {"$group": {"_id": "$year", "count": {"$sum": 1}}},
            {"$sort": {"_id": -1}},
            {"$limit": 10}
        ]
        year_stats = await self.db.cves.aggregate(year_pipeline).to_list(10)
        
        # Last sync info
        last_sync = await self.db.cve_sync_log.find_one({}, sort=[("completed_at", -1)])
        
        return {
            "total_cves": total_cves,
            "kev_count": kev_count,
            "severity_counts": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "info": severity_counts.get("info", 0)
            },
            "by_year": {y["_id"]: y["count"] for y in year_stats},
            "last_sync": {
                "completed_at": last_sync.get("completed_at") if last_sync else None,
                "source": last_sync.get("source") if last_sync else None,
                "synced_count": last_sync.get("synced_count") if last_sync else 0
            } if last_sync else None,
            "is_syncing": self._sync_status["is_running"]
        }
    
    async def full_nvd_sync(self, progress_callback=None) -> dict:
        """
        Full synchronization of ALL CVEs from NVD
        This fetches the entire NVD database (240K+ CVEs)
        """
        if self._sync_status["is_running"]:
            return {"success": False, "error": "Sync already in progress"}
        
        self._sync_status = {
            "is_running": True,
            "current_source": "NVD Full Sync",
            "progress": 0,
            "total": 0,
            "synced": 0,
            "errors": [],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "last_update": datetime.now(timezone.utc).isoformat()
        }
        
        logger.info("Starting full NVD CVE database sync...")
        
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                headers = {}
                if self.nvd_api_key:
                    headers["apiKey"] = self.nvd_api_key
                
                start_index = 0
                total_results = None
                synced_count = 0
                batch_size = 500  # Bulk insert batch size
                cve_batch = []
                
                while True:
                    params = {
                        "startIndex": start_index,
                        "resultsPerPage": NVD_RESULTS_PER_PAGE
                    }
                    
                    logger.info(f"Fetching CVEs from index {start_index}...")
                    
                    try:
                        response = await client.get(
                            NVD_API_BASE,
                            params=params,
                            headers=headers
                        )
                        
                        if response.status_code == 403:
                            logger.warning("Rate limited by NVD API, waiting 30 seconds...")
                            await asyncio.sleep(30)
                            continue
                        
                        if response.status_code != 200:
                            logger.error(f"NVD API error: {response.status_code}")
                            self._sync_status["errors"].append(f"API error at index {start_index}: {response.status_code}")
                            break
                        
                        data = response.json()
                        
                        # Get total on first request
                        if total_results is None:
                            total_results = data.get("totalResults", 0)
                            self._sync_status["total"] = total_results
                            logger.info(f"Total CVEs to fetch: {total_results}")
                        
                        vulnerabilities = data.get("vulnerabilities", [])
                        
                        if not vulnerabilities:
                            break
                        
                        # Process CVEs
                        for vuln in vulnerabilities:
                            cve_entry = self._parse_nvd_cve(vuln)
                            if cve_entry:
                                cve_batch.append(cve_entry)
                        
                        # Bulk upsert when batch is full
                        if len(cve_batch) >= batch_size:
                            await self._bulk_upsert_cves(cve_batch)
                            synced_count += len(cve_batch)
                            cve_batch = []
                            
                            self._sync_status["synced"] = synced_count
                            self._sync_status["progress"] = int((synced_count / total_results) * 100)
                            self._sync_status["last_update"] = datetime.now(timezone.utc).isoformat()
                            
                            if progress_callback:
                                await progress_callback(self._sync_status)
                        
                        # Next page
                        start_index += NVD_RESULTS_PER_PAGE
                        
                        if start_index >= total_results:
                            break
                        
                        # Rate limiting
                        if self.nvd_api_key:
                            await asyncio.sleep(0.6)
                        else:
                            await asyncio.sleep(6)
                            
                    except httpx.TimeoutException:
                        logger.warning(f"Timeout at index {start_index}, retrying...")
                        self._sync_status["errors"].append(f"Timeout at index {start_index}")
                        await asyncio.sleep(10)
                        continue
                    except Exception as e:
                        logger.error(f"Error at index {start_index}: {str(e)}")
                        self._sync_status["errors"].append(f"Error at index {start_index}: {str(e)}")
                        await asyncio.sleep(5)
                        continue
                
                # Insert remaining batch
                if cve_batch:
                    await self._bulk_upsert_cves(cve_batch)
                    synced_count += len(cve_batch)
                
                # Log sync completion
                await self.db.cve_sync_log.insert_one({
                    "source": "NVD Full",
                    "started_at": self._sync_status["started_at"],
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "synced_count": synced_count,
                    "total_available": total_results,
                    "errors": self._sync_status["errors"]
                })
                
                logger.info(f"Full NVD sync completed. Synced {synced_count} CVEs.")
                
                return {
                    "success": True,
                    "synced": synced_count,
                    "total": total_results,
                    "errors": self._sync_status["errors"]
                }
                
        except Exception as e:
            logger.error(f"Full sync failed: {str(e)}")
            return {"success": False, "error": str(e)}
        finally:
            self._sync_status["is_running"] = False
    
    async def incremental_sync(self, days_back: int = 7) -> dict:
        """
        Incremental sync - only fetch recently modified CVEs
        Should be run daily/weekly after full sync
        """
        if self._sync_status["is_running"]:
            return {"success": False, "error": "Sync already in progress"}
        
        self._sync_status = {
            "is_running": True,
            "current_source": f"NVD Incremental ({days_back} days)",
            "progress": 0,
            "total": 0,
            "synced": 0,
            "errors": [],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "last_update": datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Starting incremental CVE sync (last {days_back} days)...")
        
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                headers = {}
                if self.nvd_api_key:
                    headers["apiKey"] = self.nvd_api_key
                
                end_date = datetime.now(timezone.utc)
                start_date = end_date - timedelta(days=days_back)
                
                start_index = 0
                total_results = None
                synced_count = 0
                cve_batch = []
                
                while True:
                    params = {
                        "lastModStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                        "lastModEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
                        "startIndex": start_index,
                        "resultsPerPage": NVD_RESULTS_PER_PAGE
                    }
                    
                    try:
                        response = await client.get(NVD_API_BASE, params=params, headers=headers)
                        
                        if response.status_code == 403:
                            await asyncio.sleep(30)
                            continue
                        
                        if response.status_code != 200:
                            break
                        
                        data = response.json()
                        
                        if total_results is None:
                            total_results = data.get("totalResults", 0)
                            self._sync_status["total"] = total_results
                            logger.info(f"Incremental: {total_results} modified CVEs to sync")
                        
                        vulnerabilities = data.get("vulnerabilities", [])
                        if not vulnerabilities:
                            break
                        
                        for vuln in vulnerabilities:
                            cve_entry = self._parse_nvd_cve(vuln)
                            if cve_entry:
                                cve_batch.append(cve_entry)
                        
                        if len(cve_batch) >= 500:
                            await self._bulk_upsert_cves(cve_batch)
                            synced_count += len(cve_batch)
                            cve_batch = []
                            self._sync_status["synced"] = synced_count
                        
                        start_index += NVD_RESULTS_PER_PAGE
                        if start_index >= total_results:
                            break
                        
                        await asyncio.sleep(0.6 if self.nvd_api_key else 6)
                        
                    except Exception as e:
                        logger.error(f"Incremental sync error: {str(e)}")
                        await asyncio.sleep(5)
                        continue
                
                if cve_batch:
                    await self._bulk_upsert_cves(cve_batch)
                    synced_count += len(cve_batch)
                
                await self.db.cve_sync_log.insert_one({
                    "source": "NVD Incremental",
                    "started_at": self._sync_status["started_at"],
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "synced_count": synced_count,
                    "days_back": days_back
                })
                
                logger.info(f"Incremental sync completed. Updated {synced_count} CVEs.")
                return {"success": True, "synced": synced_count}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            self._sync_status["is_running"] = False
    
    async def sync_cisa_kev(self) -> dict:
        """
        Sync CISA Known Exploited Vulnerabilities (KEV) catalog
        These are CVEs with confirmed active exploitation
        """
        logger.info("Syncing CISA KEV catalog...")
        
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.get(CISA_KEV_URL)
                
                if response.status_code != 200:
                    return {"success": False, "error": f"CISA API error: {response.status_code}"}
                
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                kev_cve_ids = []
                kev_entries = []
                
                for vuln in vulnerabilities:
                    cve_id = vuln.get("cveID")
                    if not cve_id:
                        continue
                    
                    kev_cve_ids.append(cve_id)
                    
                    kev_entries.append({
                        "cve_id": cve_id,
                        "vendor_project": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "vulnerability_name": vuln.get("vulnerabilityName"),
                        "date_added": vuln.get("dateAdded"),
                        "short_description": vuln.get("shortDescription"),
                        "required_action": vuln.get("requiredAction"),
                        "due_date": vuln.get("dueDate"),
                        "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                        "notes": vuln.get("notes", "")
                    })
                
                # Update CVEs with KEV flag
                if kev_cve_ids:
                    # First, reset all KEV flags
                    await self.db.cves.update_many(
                        {"is_kev": True},
                        {"$set": {"is_kev": False}}
                    )
                    
                    # Set KEV flag for known exploited CVEs
                    await self.db.cves.update_many(
                        {"cve_id": {"$in": kev_cve_ids}},
                        {"$set": {"is_kev": True}}
                    )
                
                # Store KEV details separately
                await self.db.kev_catalog.delete_many({})
                if kev_entries:
                    await self.db.kev_catalog.insert_many(kev_entries)
                
                await self.db.cve_sync_log.insert_one({
                    "source": "CISA KEV",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "synced_count": len(kev_entries)
                })
                
                logger.info(f"CISA KEV sync completed. {len(kev_entries)} known exploited vulnerabilities.")
                
                return {
                    "success": True,
                    "synced": len(kev_entries),
                    "catalog_date": data.get("catalogVersion"),
                    "title": data.get("title")
                }
                
        except Exception as e:
            logger.error(f"CISA KEV sync error: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _parse_nvd_cve(self, vuln: dict) -> Optional[dict]:
        """Parse NVD CVE entry into our schema"""
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        
        if not cve_id:
            return None
        
        # Extract CVSS scores (prefer v3.1 > v3.0 > v2)
        cvss_v3_score = None
        cvss_v3_vector = None
        cvss_v2_score = None
        severity = "info"
        
        metrics = cve.get("metrics", {})
        
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")
        
        if "cvssMetricV2" in metrics:
            cvss_v2_data = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_v2_score = cvss_v2_data.get("baseScore")
        
        # Determine severity
        score = cvss_v3_score or cvss_v2_score
        if score:
            if score >= 9.0:
                severity = "critical"
            elif score >= 7.0:
                severity = "high"
            elif score >= 4.0:
                severity = "medium"
            elif score > 0:
                severity = "low"
        
        # Extract description (English preferred)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Extract CPE matches (for vulnerability matching)
        cpe_matches = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpe_matches.append({
                            "criteria": match.get("criteria"),
                            "version_start": match.get("versionStartIncluding") or match.get("versionStartExcluding"),
                            "version_end": match.get("versionEndIncluding") or match.get("versionEndExcluding")
                        })
        
        # Extract references
        references = []
        for ref in cve.get("references", []):
            references.append({
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags", [])
            })
        
        # Extract weaknesses (CWE)
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    weaknesses.append(desc.get("value"))
        
        return {
            "cve_id": cve_id,
            "description": description[:4000] if description else "",
            "severity": severity,
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_vector": cvss_v3_vector,
            "cvss_v2_score": cvss_v2_score,
            "cpe_matches": cpe_matches[:50],  # Limit to avoid huge documents
            "references": references[:20],
            "weaknesses": weaknesses,
            "published_date": cve.get("published"),
            "modified_date": cve.get("lastModified"),
            "is_kev": False,  # Will be updated by KEV sync
            "synced_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def _bulk_upsert_cves(self, cves: List[dict]):
        """Bulk upsert CVEs using unordered bulk write"""
        from pymongo import UpdateOne
        
        operations = [
            UpdateOne(
                {"cve_id": cve["cve_id"]},
                {"$set": cve},
                upsert=True
            )
            for cve in cves
        ]
        
        if operations:
            await self.db.cves.bulk_write(operations, ordered=False)
    
    async def search_cves(
        self,
        query: Optional[str] = None,
        severity: Optional[str] = None,
        is_kev: Optional[bool] = None,
        year: Optional[int] = None,
        cpe_vendor: Optional[str] = None,
        cpe_product: Optional[str] = None,
        min_cvss: Optional[float] = None,
        skip: int = 0,
        limit: int = 50
    ) -> dict:
        """Search and filter CVEs"""
        filter_query = {}
        
        if query:
            filter_query["$or"] = [
                {"cve_id": {"$regex": query, "$options": "i"}},
                {"description": {"$regex": query, "$options": "i"}}
            ]
        
        if severity:
            filter_query["severity"] = severity
        
        if is_kev is not None:
            filter_query["is_kev"] = is_kev
        
        if year:
            filter_query["cve_id"] = {"$regex": f"^CVE-{year}-"}
        
        if cpe_vendor:
            filter_query["cpe_matches.criteria"] = {"$regex": f":.*:{cpe_vendor}:", "$options": "i"}
        
        if cpe_product:
            filter_query["cpe_matches.criteria"] = {"$regex": f":.*:.*:{cpe_product}:", "$options": "i"}
        
        if min_cvss:
            filter_query["$or"] = [
                {"cvss_v3_score": {"$gte": min_cvss}},
                {"cvss_v2_score": {"$gte": min_cvss}}
            ]
        
        # Get total count
        total = await self.db.cves.count_documents(filter_query)
        
        # Get results
        cursor = self.db.cves.find(filter_query, {"_id": 0})
        cursor = cursor.sort("cvss_v3_score", -1).skip(skip).limit(limit)
        results = await cursor.to_list(limit)
        
        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "results": results
        }
    
    async def get_kev_details(self, cve_id: str) -> Optional[dict]:
        """Get CISA KEV details for a CVE"""
        return await self.db.kev_catalog.find_one({"cve_id": cve_id}, {"_id": 0})
    
    async def match_cves_by_cpe(self, cpe_string: str) -> List[dict]:
        """Find CVEs matching a CPE string"""
        # Simple CPE matching - in production, use proper CPE parsing
        filter_query = {
            "cpe_matches.criteria": {"$regex": cpe_string.replace("*", ".*"), "$options": "i"}
        }
        
        cursor = self.db.cves.find(filter_query, {"_id": 0})
        cursor = cursor.sort("cvss_v3_score", -1).limit(100)
        return await cursor.to_list(100)


# Global instance holder
_cve_manager_instance = None

def get_cve_manager(db, nvd_api_key: Optional[str] = None) -> CVEManager:
    """Get or create CVE manager instance"""
    global _cve_manager_instance
    if _cve_manager_instance is None:
        _cve_manager_instance = CVEManager(db, nvd_api_key)
    return _cve_manager_instance
