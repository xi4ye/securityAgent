"""
SecurityOrchestrator - 基于LangGraph的多Agent编排器

使用LangGraph实现Agent间的协调和循环执行
"""

import asyncio
import time
from typing import TypedDict, List, Dict, Any, Optional
from datetime import datetime
from langgraph.graph import StateGraph, END
from loguru import logger

from models import (
    SecurityLog, AlertResult, EnrichedEvent, VulnResult,
    RemediationResult, ActionResult, AnalysisReport, AgentResult
)
from agents.log_collector_agent import LogCollectorAgent
from agents.alert_analysis_agent import AlertAnalysisAgent
from agents.threat_intel_agent import ThreatIntelAgent
from agents.vuln_hunting_agent import VulnHuntingAgent
from agents.remediation_agent import RemediationAgent
from agents.security_report_agent import SecurityReportAgent


class SecurityState(TypedDict):
    """全局状态定义 - LangGraph会在Agent间自动传递"""
    task: str
    source: str
    limit: Optional[int]

    logs: List[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    threats: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    remediations: List[Dict[str, Any]]
    report: Optional[str]

    current_agent: str
    iteration: int
    max_iterations: int

    error: Optional[str]
    execution_times: Dict[str, float]


class SecurityOrchestrator:
    """
    SecurityOrchestrator - 基于LangGraph的安全Agent编排器

    工作流：
    LogCollector → AlertAnalysis → ThreatIntel → VulnHunting → Remediation → Report
    """

    def __init__(self, max_retries: int = 3):
        self.max_retries = max_retries
        self.graph = None
        self._build_graph()
        logger.info("[SecurityOrchestrator] Initialized with LangGraph")

    def _build_graph(self):
        """构建LangGraph工作流"""
        workflow = StateGraph(SecurityState)

        workflow.add_node("log_collector", self._log_collector_node)
        workflow.add_node("alert_analysis", self._alert_analysis_node)
        workflow.add_node("threat_intel", self._threat_intel_node)
        workflow.add_node("vuln_hunting", self._vuln_hunting_node)
        workflow.add_node("remediation", self._remediation_node)
        workflow.add_node("report_generator", self._report_generator_node)

        workflow.set_entry_point("log_collector")

        workflow.add_edge("log_collector", "alert_analysis")
        workflow.add_edge("alert_analysis", "threat_intel")
        workflow.add_edge("threat_intel", "vuln_hunting")
        workflow.add_edge("vuln_hunting", "remediation")
        workflow.add_edge("remediation", "report_generator")
        workflow.add_edge("report_generator", END)

        self.graph = workflow.compile()

    async def _log_collector_node(self, state: SecurityState) -> SecurityState:
        """日志采集节点"""
        node_name = "log_collector"
        logger.info(f"[SecurityOrchestrator] Node: {node_name}")
        state["current_agent"] = node_name

        start_time = time.time()
        try:
            agent = LogCollectorAgent()

            logs = await agent.collect_logs(
                source=state.get("source", "nsl_kdd"),
                limit=state.get("limit")
            )

            standardized_logs = await agent.standardize_logs(logs)

            state["logs"] = [log.model_dump() if hasattr(log, 'model_dump') else log for log in standardized_logs]
            state["error"] = None

        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in {node_name}: {e}")
            state["error"] = str(e)
            state["logs"] = []

        state["execution_times"][node_name] = time.time() - start_time
        return state

    async def _alert_analysis_node(self, state: SecurityState) -> SecurityState:
        """告警分析节点"""
        node_name = "alert_analysis"
        logger.info(f"[SecurityOrchestrator] Node: {node_name}")
        state["current_agent"] = node_name

        start_time = time.time()
        try:
            agent = AlertAnalysisAgent()
            alerts = []

            logs = state.get("logs", [])
            for log in logs:
                log_obj = SecurityLog(**log) if isinstance(log, dict) else log
                result = await agent.analyze_alert(log_obj)

                if hasattr(result, 'model_dump'):
                    result_dict = result.model_dump()
                else:
                    result_dict = result

                if result_dict.get("is_threat", False):
                    alerts.append(result_dict)

            state["alerts"] = alerts
            state["error"] = None

        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in {node_name}: {e}")
            state["error"] = str(e)
            state["alerts"] = []

        state["execution_times"][node_name] = time.time() - start_time
        return state

    async def _threat_intel_node(self, state: SecurityState) -> SecurityState:
        """威胁情报节点"""
        node_name = "threat_intel"
        logger.info(f"[SecurityOrchestrator] Node: {node_name}")
        state["current_agent"] = node_name

        start_time = time.time()
        try:
            agent = ThreatIntelAgent()

            alerts = state.get("alerts", [])
            for alert in alerts:
                enriched_alert = await agent.enrich_event(AlertResult(**alert))

                if hasattr(enriched_alert, 'model_dump'):
                    alert["threat_intel"] = enriched_alert.model_dump().get("threat_intel")
                else:
                    alert["threat_intel"] = enriched_alert.get("threat_intel")

            state["threats"] = alerts
            state["error"] = None

        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in {node_name}: {e}")
            state["error"] = str(e)
            state["threats"] = state.get("alerts", [])

        state["execution_times"][node_name] = time.time() - start_time
        return state

    async def _vuln_hunting_node(self, state: SecurityState) -> SecurityState:
        """漏洞分析节点"""
        node_name = "vuln_hunting"
        logger.info(f"[SecurityOrchestrator] Node: {node_name}")
        state["current_agent"] = node_name

        start_time = time.time()
        try:
            agent = VulnHuntingAgent()
            vulnerabilities = []

            alerts = state.get("alerts", [])
            for alert in alerts:
                enriched_event = EnrichedEvent(
                    original_alert=AlertResult(**alert),
                    threat_intel=alert.get("threat_intel", {}),
                    enriched_timestamp=datetime.now().isoformat()
                )

                vuln_result = await agent.analyze_vulnerability(enriched_event)

                if vuln_result:
                    if hasattr(vuln_result, 'model_dump'):
                        vulnerabilities.append(vuln_result.model_dump())
                    else:
                        vulnerabilities.append(vuln_result)

            state["vulnerabilities"] = vulnerabilities
            state["error"] = None

        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in {node_name}: {e}")
            state["error"] = str(e)
            state["vulnerabilities"] = []

        state["execution_times"][node_name] = time.time() - start_time
        return state

    async def _remediation_node(self, state: SecurityState) -> SecurityState:
        """响应处置节点"""
        node_name = "remediation"
        logger.info(f"[SecurityOrchestrator] Node: {node_name}")
        state["current_agent"] = node_name

        start_time = time.time()
        try:
            agent = RemediationAgent()
            remediations = []

            vulnerabilities = state.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                vuln_obj = VulnResult(**vuln) if isinstance(vuln, dict) else vuln
                remediation = await agent.generate_remediation(vuln_obj)

                if hasattr(remediation, 'model_dump'):
                    remediations.append(remediation.model_dump())
                else:
                    remediations.append(remediation)

            state["remediations"] = remediations
            state["error"] = None

        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in {node_name}: {e}")
            state["error"] = str(e)
            state["remediations"] = []

        state["execution_times"][node_name] = time.time() - start_time
        return state

    async def _report_generator_node(self, state: SecurityState) -> SecurityState:
        """报告生成节点"""
        node_name = "report_generator"
        logger.info(f"[SecurityOrchestrator] Node: {node_name}")
        state["current_agent"] = node_name

        start_time = time.time()
        try:
            agent = SecurityReportAgent()

            logs = [SecurityLog(**log) if isinstance(log, dict) else log
                   for log in state.get("logs", [])]

            alerts = [AlertResult(**alert) if isinstance(alert, dict) else alert
                     for alert in state.get("alerts", [])]

            vulnerabilities = [VulnResult(**vuln) if isinstance(vuln, dict) else vuln
                             for vuln in state.get("vulnerabilities", [])]

            remediations = [RemediationResult(**rem) if isinstance(rem, dict) else rem
                           for rem in state.get("remediations", [])]

            report = await agent.generate_report(
                logs=logs,
                alerts=alerts,
                vulnerabilities=vulnerabilities,
                remediations=remediations
            )

            state["report"] = report
            state["error"] = None

        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in {node_name}: {e}")
            state["error"] = str(e)
            state["report"] = None

        state["execution_times"][node_name] = time.time() - start_time
        return state

    async def execute(
        self,
        task: str,
        source: str = "nsl_kdd",
        limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        执行安全分析任务

        Args:
            task: 任务描述
            source: 数据来源
            limit: 处理数量限制

        Returns:
            执行结果（包含报告）
        """
        logger.info(f"[SecurityOrchestrator] Executing task: {task}")

        start_time = time.time()

        initial_state = SecurityState(
            task=task,
            source=source,
            limit=limit,
            logs=[],
            alerts=[],
            threats=[],
            vulnerabilities=[],
            remediations=[],
            report=None,
            current_agent="",
            iteration=0,
            max_iterations=10,
            error=None,
            execution_times={}
        )

        try:
            result = await self.graph.ainvoke(initial_state)
            result["total_execution_time"] = time.time() - start_time
            result["status"] = "success" if not result.get("error") else "error"

            logger.info(f"[SecurityOrchestrator] Task completed in {result['total_execution_time']:.2f}s")
            return result

        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Task failed: {e}")
            return {
                **initial_state,
                "error": str(e),
                "status": "error",
                "total_execution_time": time.time() - start_time
            }

    def visualize(self) -> Any:
        """可视化工作流图"""
        return self.graph.get_graph().draw_mermaid()


async def main():
    """测试运行"""
    orchestrator = SecurityOrchestrator()

    result = await orchestrator.execute(
        task="分析过去24小时的安全告警",
        source="nsl_kdd",
        limit=10
    )

    print(f"Status: {result.get('status')}")
    print(f"Logs: {len(result.get('logs', []))}")
    print(f"Alerts: {len(result.get('alerts', []))}")
    print(f"Vulnerabilities: {len(result.get('vulnerabilities', []))}")
    print(f"Execution times: {result.get('execution_times', {})}")


if __name__ == "__main__":
    asyncio.run(main())
