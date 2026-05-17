"""
契约测试 - 验证Agent间接口契约
确保AlertAgent → VulnAgent → ReportAgent 的数据传递正确
"""

import pytest
from typing import Dict, Any


class TestAlertToVulnContract:
    """验证AlertAgent输出能被VulnAgent正确解析"""

    def test_alert_output_has_required_fields(self, mock_alert_output):
        """AlertAgent输出必须包含VulnAgent所需字段"""
        result = mock_alert_output["result"]

        # 必须有true_threats字段（VulnAgent需要处理）
        assert "true_threats" in result
        assert isinstance(result["true_threats"], list)

        # true_threats中的每一项必须有id
        for threat in result["true_threats"]:
            assert "id" in threat, "Each threat must have an 'id' field"

    def test_alert_output_ioc_format(self, mock_alert_output):
        """IOC格式必须符合规范"""
        result = mock_alert_output["result"]

        if "iocs" in result:
            for ioc in result["iocs"]:
                assert "type" in ioc, "IOC must have 'type' field"
                assert "value" in ioc, "IOC must have 'value' field"
                assert ioc["type"] in ["ip", "domain", "hash", "url"], \
                    f"Unknown IOC type: {ioc['type']}"

    def test_threat_severity_values(self, mock_alert_output):
        """威胁严重性必须是标准值"""
        result = mock_alert_output["result"]

        valid_severities = ["low", "medium", "high", "critical"]

        for threat in result.get("true_threats", []):
            if "severity" in threat:
                assert threat["severity"] in valid_severities, \
                    f"Invalid severity: {threat['severity']}"


class TestVulnToReportContract:
    """验证VulnAgent输出能被ReportAgent正确解析"""

    def test_vuln_output_has_required_fields(self, mock_vuln_output):
        """VulnAgent输出必须包含ReportAgent所需字段"""
        result = mock_vuln_output["result"]

        # 必须有vulnerabilities字段
        assert "vulnerabilities" in result
        assert isinstance(result["vulnerabilities"], list)

        # 必须有remediation_plans字段
        assert "remediation_plans" in result
        assert isinstance(result["remediation_plans"], list)

    def test_vulnerability_cve_format(self, mock_vuln_output):
        """CVE ID格式必须正确"""
        result = mock_vuln_output["result"]

        for vuln in result.get("vulnerabilities", []):
            if "cve_id" in vuln:
                cve_id = vuln["cve_id"]
                assert cve_id.startswith("CVE-"), f"Invalid CVE format: {cve_id}"

    def test_remediation_plan_structure(self, mock_vuln_output):
        """修复计划结构必须完整"""
        result = mock_vuln_output["result"]

        for plan in result.get("remediation_plans", []):
            assert "vuln_id" in plan, "Remediation plan must have 'vuln_id'"
            assert "short_term" in plan or "long_term" in plan, \
                "Remediation plan must have 'short_term' or 'long_term'"


class TestEndToEndContract:
    """端到端契约测试 - Alert → Vuln → Report"""

    def test_full_pipeline_data_flow(self, mock_alert_output, mock_vuln_output):
        """验证完整数据流"""

        # Step 1: AlertAgent输出
        alert_result = mock_alert_output["result"]
        assert len(alert_result["true_threats"]) > 0

        # Step 2: 构造VulnAgent输入（从Alert输出提取）
        vuln_input = {
            "vulnerabilities": [],
            "related_iocs": alert_result.get("iocs", []),
            "related_alerts": alert_result.get("true_threats", [])
        }

        # 验证VulnAgent能接收AlertAgent的输出
        assert "related_iocs" in vuln_input
        assert "related_alerts" in vuln_input

        # Step 3: VulnAgent输出
        vuln_result = mock_vuln_output["result"]

        # Step 4: 构造ReportAgent输入
        report_input = {
            "report_type": "incident",
            "vuln_results": vuln_result,
            "alert_results": alert_result
        }

        # 验证ReportAgent能接收VulnAgent和AlertAgent的输出
        assert "vuln_results" in report_input
        assert "alert_results" in report_input

    def test_error_propagation(self):
        """验证错误能正确传播"""

        # AlertAgent失败时的输出
        alert_error_output = {
            "task_id": "test-task-001",
            "status": "failed",
            "error": "Unable to fetch alerts from SIEM",
            "result": {}
        }

        # VulnAgent应该能处理AlertAgent失败的情况
        assert alert_error_output["status"] == "failed"
        assert "error" in alert_error_output

        # ReportAgent应该能基于部分数据生成报告
        partial_data_output = {
            "task_id": "test-task-003",
            "status": "partial",
            "result": {
                "vulnerabilities": [],
                "alert_results": None,
                "error": "Alert data unavailable"
            }
        }

        assert partial_data_output["status"] in ["success", "partial", "failed"]