"""
Mock Agents - 用于独立测试
模拟其他Agent的输出，允许独立开发和测试
"""

from typing import Dict, Any


class MockAlertAgent:
    """Mock AlertAnalysisAgent，用于测试"""

    async def execute(self, task_id: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        模拟AlertAnalysisAgent的execute方法
        返回标准化的AgentOutput格式
        """
        return {
            "task_id": task_id,
            "status": "success",
            "result": {
                "total_analyzed": len(input_data.get("alerts", [])),
                "true_threats": [
                    {
                        "id": f"mock-threat-{i}",
                        "type": "bruteforce",
                        "severity": "medium",
                        "source_ip": f"192.168.1.{100+i}"
                    }
                    for i in range(min(3, len(input_data.get("alerts", []))))
                ] if input_data.get("alerts") else [],
                "false_positives": [],
                "needs_investigation": [],
                "confidence": 0.9,
                "recommended_actions": ["review_logs", "block_ip"],
                "iocs": [
                    {"type": "ip", "value": "192.168.1.101"}
                ],
                "affected_assets": ["server-001"]
            },
            "metadata": {
                "execution_time_ms": 150,
                "model": "deepseek-chat"
            }
        }


class MockVulnAgent:
    """Mock VulnHuntingAgent，用于测试"""

    async def execute(self, task_id: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        模拟VulnHuntingAgent的execute方法
        """
        vulns = input_data.get("vulnerabilities", [])

        return {
            "task_id": task_id,
            "status": "success",
            "result": {
                "total_analyzed": len(vulns),
                "vulnerabilities": [
                    {
                        "cve_id": f"MOCK-{2024}-{1000+i}",
                        "severity": "high" if i == 0 else "medium",
                        "affected_endpoint": f"server-{i:03d}"
                    }
                    for i in range(len(vulns))
                ] if vulns else [],
                "high_risk_count": len(vulns),
                "remediation_plans": [
                    {
                        "vuln_id": f"MOCK-{2024}-{1000+i}",
                        "short_term": "Apply temporary patch",
                        "long_term": "Schedule system upgrade"
                    }
                    for i in range(len(vulns))
                ] if vulns else []
            },
            "metadata": {
                "execution_time_ms": 200,
                "model": "deepseek-chat"
            }
        }


class MockReportAgent:
    """Mock ReportGeneratorAgent，用于测试"""

    async def execute(self, task_id: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        模拟ReportGeneratorAgent的execute方法
        """
        report_type = input_data.get("report_type", "incident")

        return {
            "task_id": task_id,
            "status": "success",
            "result": {
                "report_id": f"mock-report-{task_id}",
                "report_content": f"# Mock {report_type.title()} Security Report\n\n"
                                 f"Generated at: 2024-01-15\n\n"
                                 f"## Summary\n\n"
                                 f"This is a mock report for testing purposes.\n\n"
                                 f"## Findings\n\n"
                                 f"- Multiple security events detected\n"
                                 f"- Threats have been contained\n\n"
                                 f"## Recommendations\n\n"
                                 f"1. Continue monitoring\n"
                                 f"2. Apply security patches\n",
                "summary": "Mock report summary - testing only",
                "key_findings": [
                    "Finding 1: Mock malware detected and blocked",
                    "Finding 2: Suspicious login attempts identified"
                ],
                "recommendations": [
                    "Continue security monitoring",
                    "Review access controls"
                ],
                "confidence": 0.85
            },
            "metadata": {
                "execution_time_ms": 100,
                "model": "deepseek-chat"
            }
        }


class MockOrchestrator:
    """Mock SecurityOrchestrator，用于端到端测试"""

    def __init__(self):
        self.alert_agent = MockAlertAgent()
        self.vuln_agent = MockVulnAgent()
        self.report_agent = MockReportAgent()

    async def process_request(self, user_request: str) -> Dict[str, Any]:
        """模拟完整的处理流程"""
        task_id = "mock-task-001"

        # 模拟处理
        return {
            "success": True,
            "task_id": task_id,
            "result": {
                "alert_analysis": await self.alert_agent.execute(task_id, {}),
                "vuln_analysis": await self.vuln_agent.execute(task_id, {}),
                "final_report": await self.report_agent.execute(task_id, {})
            }
        }