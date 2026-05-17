"""
SecurityOrchestrator - 基于LangGraph的多Agent编排器

使用LangGraph实现Agent间的协调和循环执行
"""

from typing import TypedDict, List, Dict, Any, Optional
from langgraph.graph import StateGraph, END
from loguru import logger

from agents.log_collector_agent import LogCollectorAgent
from agents.alert_analysis_agent import AlertAnalysisAgent
from agents.threat_intel_agent import ThreatIntelAgent
from agents.vuln_hunting_agent import VulnHuntingAgent
from agents.remediation_agent import RemediationAgent
from agents.security_report_agent import SecurityReportAgent


class SecurityState(TypedDict):
    """
    全局状态定义 - LangGraph会在Agent间自动传递
    """
    # 输入
    task: str
    source: str
    limit: Optional[int]

    # 中间结果
    logs: List[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    threats: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    remediations: List[Dict[str, Any]]
    report: Optional[str]

    # 状态标记
    current_agent: str
    iteration: int
    max_iterations: int

    # 错误信息
    error: Optional[str]


class SecurityOrchestrator:
    """
    SecurityOrchestrator - 基于LangGraph的安全Agent编排器

    工作流：
    LogCollector → AlertAnalysis → [ThreatIntel] → VulnHunting → Remediation → Report
    """

    def __init__(self):
        self.graph = None
        self._build_graph()
        logger.info("[SecurityOrchestrator] Initialized with LangGraph")

    def _build_graph(self):
        """构建LangGraph工作流"""
        workflow = StateGraph(SecurityState)

        # 添加节点（Agent）
        workflow.add_node("log_collector", self._log_collector_node)
        workflow.add_node("alert_analysis", self._alert_analysis_node)
        workflow.add_node("threat_intel", self._threat_intel_node)
        workflow.add_node("vuln_hunting", self._vuln_hunting_node)
        workflow.add_node("remediation", self._remediation_node)
        workflow.add_node("report_generator", self._report_generator_node)

        # 设置入口点
        workflow.set_entry_point("log_collector")

        # 添加边（工作流连接）
        workflow.add_edge("log_collector", "alert_analysis")
        workflow.add_edge("alert_analysis", "threat_intel")
        workflow.add_edge("threat_intel", "vuln_hunting")
        workflow.add_edge("vuln_hunting", "remediation")
        workflow.add_edge("remediation", "report_generator")
        workflow.add_edge("report_generator", END)

        # 编译图
        self.graph = workflow.compile()

    async def _log_collector_node(self, state: SecurityState) -> SecurityState:
        """日志采集节点"""
        logger.info("[SecurityOrchestrator] Node: log_collector")

        try:
            agent = LogCollectorAgent()
            logs = await agent.collect_logs(
                source=state.get("source", "nsl_kdd"),
                limit=state.get("limit")
            )
            standardized_logs = await agent.standardize_logs(logs)

            state["logs"] = standardized_logs
            state["current_agent"] = "log_collector"
            state["error"] = None
        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in log_collector: {e}")
            state["error"] = str(e)

        return state

    async def _alert_analysis_node(self, state: SecurityState) -> SecurityState:
        """告警分析节点"""
        logger.info("[SecurityOrchestrator] Node: alert_analysis")

        try:
            agent = AlertAnalysisAgent()
            alerts = []

            for log in state.get("logs", []):
                result = await agent.analyze_alert(log)
                if result.get("is_threat", False):
                    alerts.append(result)

            state["alerts"] = alerts
            state["current_agent"] = "alert_analysis"
        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in alert_analysis: {e}")
            state["error"] = str(e)

        return state

    async def _threat_intel_node(self, state: SecurityState) -> SecurityState:
        """威胁情报节点"""
        logger.info("[SecurityOrchestrator] Node: threat_intel")

        try:
            agent = ThreatIntelAgent()

            for alert in state.get("alerts", []):
                enriched_alert = await agent.enrich_event(alert)
                alert["threat_intel"] = enriched_alert.get("threat_intel")

            state["current_agent"] = "threat_intel"
        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in threat_intel: {e}")
            state["error"] = str(e)

        return state

    async def _vuln_hunting_node(self, state: SecurityState) -> SecurityState:
        """漏洞分析节点"""
        logger.info("[SecurityOrchestrator] Node: vuln_hunting")

        try:
            agent = VulnHuntingAgent()
            vulnerabilities = []

            for alert in state.get("alerts", []):
                vuln_result = await agent.analyze_vulnerability(alert)
                if vuln_result:
                    vulnerabilities.append(vuln_result)

            state["vulnerabilities"] = vulnerabilities
            state["current_agent"] = "vuln_hunting"
        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in vuln_hunting: {e}")
            state["error"] = str(e)

        return state

    async def _remediation_node(self, state: SecurityState) -> SecurityState:
        """响应处置节点"""
        logger.info("[SecurityOrchestrator] Node: remediation")

        try:
            agent = RemediationAgent()
            remediations = []

            for vuln in state.get("vulnerabilities", []):
                remediation = await agent.generate_remediation(vuln)
                remediations.append(remediation)

            state["remediations"] = remediations
            state["current_agent"] = "remediation"
        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in remediation: {e}")
            state["error"] = str(e)

        return state

    async def _report_generator_node(self, state: SecurityState) -> SecurityState:
        """报告生成节点"""
        logger.info("[SecurityOrchestrator] Node: report_generator")

        try:
            agent = SecurityReportAgent()
            report = await agent.generate_report(
                logs=state.get("logs", []),
                alerts=state.get("alerts", []),
                vulnerabilities=state.get("vulnerabilities", []),
                remediations=state.get("remediations", [])
            )

            state["report"] = report
            state["current_agent"] = "report_generator"
        except Exception as e:
            logger.error(f"[SecurityOrchestrator] Error in report_generator: {e}")
            state["error"] = str(e)

        return state

    async def execute(self, task: str, source: str = "nsl_kdd", limit: Optional[int] = None) -> Dict[str, Any]:
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
            error=None
        )

        result = await self.graph.ainvoke(initial_state)

        logger.info("[SecurityOrchestrator] Task completed")
        return result

    def visualize(self) -> Any:
        """
        可视化工作流图

        Returns:
            可视化对象（可以在Jupyter中显示）
        """
        return self.graph.get_graph().draw_mermaid()
