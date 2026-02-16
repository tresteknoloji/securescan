"""
Real Risk Score Calculator
Combines CVSS + KEV + Active Verification + Exposure for accurate risk assessment
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ExposureLevel(Enum):
    """Network exposure levels"""
    INTERNET = "internet"      # Directly accessible from internet
    DMZ = "dmz"               # In DMZ, limited exposure
    INTERNAL = "internal"      # Internal network only
    ISOLATED = "isolated"      # Air-gapped or isolated


class RiskLevel(Enum):
    """Risk severity levels based on Real Risk Score"""
    CRITICAL = "critical"  # 9.0 - 10.0
    HIGH = "high"          # 7.0 - 8.9
    MEDIUM = "medium"      # 4.0 - 6.9
    LOW = "low"            # 0.1 - 3.9
    INFO = "info"          # 0.0


@dataclass
class RiskFactors:
    """Individual risk factors for a vulnerability"""
    cvss_base: float = 0.0
    is_kev: bool = False                    # Known Exploited Vulnerability
    is_verified: bool = False               # Verified by active check
    exposure: ExposureLevel = ExposureLevel.INTERNAL
    has_public_exploit: bool = False        # Exploit available publicly
    is_default_creds: bool = False          # Uses default credentials
    data_sensitivity: str = "normal"        # normal, sensitive, critical
    

class RiskCalculator:
    """
    Calculates Real Risk Score based on multiple factors
    
    Formula:
    Real Risk = min(10.0, CVSS_Base × Exposure_Multiplier + Bonuses)
    
    Bonuses:
    - KEV (Known Exploited): +1.5
    - Active Verification: +1.0
    - Public Exploit: +0.5
    - Default Credentials: +1.0
    
    Exposure Multipliers:
    - Internet: 1.3
    - DMZ: 1.1
    - Internal: 1.0
    - Isolated: 0.8
    """
    
    # Exposure multipliers
    EXPOSURE_MULTIPLIERS = {
        ExposureLevel.INTERNET: 1.3,
        ExposureLevel.DMZ: 1.1,
        ExposureLevel.INTERNAL: 1.0,
        ExposureLevel.ISOLATED: 0.8,
    }
    
    # Bonus points
    KEV_BONUS = 1.5           # Known to be actively exploited
    VERIFIED_BONUS = 1.0      # Confirmed by active check
    PUBLIC_EXPLOIT_BONUS = 0.5
    DEFAULT_CREDS_BONUS = 1.0
    
    # Data sensitivity multipliers
    DATA_SENSITIVITY_MULTIPLIERS = {
        "normal": 1.0,
        "sensitive": 1.1,
        "critical": 1.2,
    }
    
    @classmethod
    def calculate(cls, factors: RiskFactors) -> Dict[str, Any]:
        """
        Calculate Real Risk Score
        
        Returns:
            {
                "real_risk_score": float,
                "risk_level": str,
                "factors_breakdown": dict,
                "recommendation_priority": int
            }
        """
        # Start with CVSS base
        base_score = factors.cvss_base or 0.0
        
        # Apply exposure multiplier
        exposure_mult = cls.EXPOSURE_MULTIPLIERS.get(factors.exposure, 1.0)
        adjusted_score = base_score * exposure_mult
        
        # Calculate bonuses
        bonuses = 0.0
        factors_applied = []
        
        if factors.is_kev:
            bonuses += cls.KEV_BONUS
            factors_applied.append({"factor": "KEV", "bonus": cls.KEV_BONUS, "reason": "Actively exploited in the wild"})
        
        if factors.is_verified:
            bonuses += cls.VERIFIED_BONUS
            factors_applied.append({"factor": "Verified", "bonus": cls.VERIFIED_BONUS, "reason": "Confirmed by active testing"})
        
        if factors.has_public_exploit:
            bonuses += cls.PUBLIC_EXPLOIT_BONUS
            factors_applied.append({"factor": "Public Exploit", "bonus": cls.PUBLIC_EXPLOIT_BONUS, "reason": "Exploit code publicly available"})
        
        if factors.is_default_creds:
            bonuses += cls.DEFAULT_CREDS_BONUS
            factors_applied.append({"factor": "Default Credentials", "bonus": cls.DEFAULT_CREDS_BONUS, "reason": "Uses default or weak credentials"})
        
        # Apply data sensitivity
        data_mult = cls.DATA_SENSITIVITY_MULTIPLIERS.get(factors.data_sensitivity, 1.0)
        
        # Final calculation
        real_risk_score = min(10.0, (adjusted_score + bonuses) * data_mult)
        real_risk_score = round(real_risk_score, 1)
        
        # Determine risk level
        risk_level = cls.get_risk_level(real_risk_score)
        
        # Calculate priority (1 = highest, 5 = lowest)
        priority = cls.get_priority(real_risk_score, factors)
        
        return {
            "real_risk_score": real_risk_score,
            "risk_level": risk_level.value,
            "cvss_base": base_score,
            "factors_breakdown": {
                "base_score": base_score,
                "exposure_multiplier": exposure_mult,
                "exposure_level": factors.exposure.value,
                "bonuses_total": bonuses,
                "bonuses_applied": factors_applied,
                "data_sensitivity_multiplier": data_mult,
            },
            "recommendation_priority": priority,
            "is_kev": factors.is_kev,
            "is_verified": factors.is_verified,
        }
    
    @classmethod
    def get_risk_level(cls, score: float) -> RiskLevel:
        """Get risk level from score"""
        if score >= 9.0:
            return RiskLevel.CRITICAL
        elif score >= 7.0:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        elif score > 0:
            return RiskLevel.LOW
        return RiskLevel.INFO
    
    @classmethod
    def get_priority(cls, score: float, factors: RiskFactors) -> int:
        """
        Get remediation priority (1-5, 1 being highest)
        
        Priority is determined by:
        1. Real Risk Score
        2. KEV status (known exploited gets higher priority)
        3. Verification status
        """
        # Base priority from score
        if score >= 9.0:
            priority = 1
        elif score >= 7.0:
            priority = 2
        elif score >= 4.0:
            priority = 3
        elif score > 0:
            priority = 4
        else:
            priority = 5
        
        # KEV always bumps to at least priority 2
        if factors.is_kev and priority > 2:
            priority = 2
        
        # Verified vulnerabilities get priority bump
        if factors.is_verified and priority > 1:
            priority -= 1
        
        return max(1, min(5, priority))
    
    @classmethod
    def calculate_for_vulnerability(
        cls,
        vuln: Dict[str, Any],
        exposure: str = "internal",
        data_sensitivity: str = "normal"
    ) -> Dict[str, Any]:
        """
        Calculate Real Risk Score for a vulnerability dict
        
        Args:
            vuln: Vulnerability dictionary with cvss_score, is_kev, source, etc.
            exposure: "internet", "dmz", "internal", "isolated"
            data_sensitivity: "normal", "sensitive", "critical"
        """
        # Parse exposure level
        try:
            exposure_level = ExposureLevel(exposure.lower())
        except ValueError:
            exposure_level = ExposureLevel.INTERNAL
        
        # Build factors
        factors = RiskFactors(
            cvss_base=vuln.get("cvss_score") or vuln.get("cvss_v3_score") or 0.0,
            is_kev=vuln.get("is_kev", False),
            is_verified=vuln.get("source") == "active_check",
            exposure=exposure_level,
            has_public_exploit=vuln.get("has_exploit", False),
            is_default_creds=vuln.get("check_name") == "Default Credentials" if vuln.get("source") == "active_check" else False,
            data_sensitivity=data_sensitivity,
        )
        
        result = cls.calculate(factors)
        
        # Merge with original vuln data
        vuln_with_risk = {**vuln, **result}
        
        return vuln_with_risk
    
    @classmethod
    def calculate_scan_summary(cls, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Calculate risk summary for entire scan
        
        Returns:
            {
                "total_vulnerabilities": int,
                "highest_risk_score": float,
                "average_risk_score": float,
                "risk_distribution": {"critical": n, "high": n, ...},
                "kev_count": int,
                "verified_count": int,
                "priority_1_count": int,
                "overall_risk_level": str,
            }
        """
        if not vulnerabilities:
            return {
                "total_vulnerabilities": 0,
                "highest_risk_score": 0.0,
                "average_risk_score": 0.0,
                "risk_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "kev_count": 0,
                "verified_count": 0,
                "priority_1_count": 0,
                "overall_risk_level": "info",
            }
        
        risk_scores = []
        risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        kev_count = 0
        verified_count = 0
        priority_1_count = 0
        
        for vuln in vulnerabilities:
            score = vuln.get("real_risk_score", vuln.get("cvss_score", 0))
            risk_scores.append(score)
            
            level = vuln.get("risk_level", cls.get_risk_level(score).value)
            if level in risk_distribution:
                risk_distribution[level] += 1
            
            if vuln.get("is_kev"):
                kev_count += 1
            
            if vuln.get("is_verified") or vuln.get("source") == "active_check":
                verified_count += 1
            
            if vuln.get("recommendation_priority") == 1:
                priority_1_count += 1
        
        highest = max(risk_scores) if risk_scores else 0.0
        average = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        
        # Overall risk level based on highest score
        overall_level = cls.get_risk_level(highest).value
        
        return {
            "total_vulnerabilities": len(vulnerabilities),
            "highest_risk_score": round(highest, 1),
            "average_risk_score": round(average, 1),
            "risk_distribution": risk_distribution,
            "kev_count": kev_count,
            "verified_count": verified_count,
            "priority_1_count": priority_1_count,
            "overall_risk_level": overall_level,
        }


def enrich_vulnerabilities_with_risk(
    vulnerabilities: List[Dict],
    exposure: str = "internal",
    data_sensitivity: str = "normal"
) -> List[Dict]:
    """
    Enrich a list of vulnerabilities with Real Risk Scores
    and sort by priority
    """
    enriched = []
    
    for vuln in vulnerabilities:
        enriched_vuln = RiskCalculator.calculate_for_vulnerability(
            vuln,
            exposure=exposure,
            data_sensitivity=data_sensitivity
        )
        enriched.append(enriched_vuln)
    
    # Sort by priority (1 first), then by real_risk_score (highest first)
    enriched.sort(key=lambda x: (x.get("recommendation_priority", 5), -x.get("real_risk_score", 0)))
    
    return enriched
