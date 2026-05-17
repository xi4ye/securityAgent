import pytest
from typing import Dict, Any


@pytest.fixture
def mock_alert_output():
    """模拟AlertAnalysisAgent的输出"""
    return {
        "task_id": "test-task-001",
        "status": "success",
        "result": {
            "total_analyzed": 10,
            "true_threats": [
                {
                    "id": "threat-001",
                    "type": "malware",
                    "severity": "high",
                    "source_ip": "192.168.1.100"
                }
            ],
            "false_positives": [],
            "needs_investigation": [],
            "confidence": 0.85,
            "recommended_actions": ["block_ip", "isolate_endpoint"],
            "iocs": [
                {"type": "ip", "value": "192.168.1.100"}
            ],
            "affected_assets": ["server-001"]
        }
    }


@pytest.fixture
def mock_vuln_output():
    """模拟VulnHuntingAgent的输出"""
    return {
        "task_id": "test-task-002",
        "status": "success",
        "result": {
            "total_analyzed": 1,
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-1234",
                    "severity": "critical",
                    "affected_endpoint": "server-001"
                }
            ],
            "high_risk_count": 1,
            "remediation_plans": [
                {
                    "vuln_id": "CVE-2024-1234",
                    "short_term": "Apply patch",
                    "long_term": "Upgrade system"
                }
            ]
        }
    }


@pytest.fixture
def sample_alert_input():
    """示例AlertAnalysisAgent输入"""
    return {
        "alerts": [
            {
                "id": "alert-001",
                "type": "login_failed",
                "source": "firewall",
                "timestamp": "2024-01-15T10:30:00Z",
                "source_ip": "192.168.1.100",
                "description": "Multiple failed login attempts"
            },
            {
                "id": "alert-002",
                "type": "malware_detected",
                "source": "edr",
                "timestamp": "2024-01-15T10:35:00Z",
                "endpoint": "server-001",
                "description": "Trojan detected"
            }
        ],
        "time_range": "24h",
        "context": {}
    }


@pytest.fixture
def sample_vuln_input():
    """示例VulnHuntingAgent输入"""
    return {
        "vulnerabilities": [
            {
                "cve_id": "CVE-2024-5678",
                "description": "Remote code execution vulnerability",
                "severity": "critical",
                "affected_system": "web-server-001"
            }
        ],
        "related_iocs": [
            {"type": "ip", "value": "192.168.1.100"}
        ],
        "related_alerts": [
            {"id": "alert-001", "type": "suspicious_activity"}
        ],
        "context": {}
    }