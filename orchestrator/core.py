from typing import Dict, Any, List
import uuid
import json
from loguru import logger

from agents import (
    AlertAnalysisAgent,
    VulnHuntingAgent,
    SecurityReportAgent
)
from tools import FirewallTool, EDRTool, LogQueryTool
from rag import KnowledgeBase
from .context import TaskContext, SharedDataStore
from .communication import AgentCommunicationProtocol
from .react import ReActExecutor
from config.settings import *


class SecurityOrchestrator:
    def __init__(self):
        from langchain_community.chat_models import ChatDeepSeek

        self.llm = ChatDeepSeek(
            model=DEEPSEEK_MODEL,
            api_key=DEEPSEEK_API_KEY,
            base_url=DEEPSEEK_API_BASE,
            temperature=0.7,
            streaming=False
        )

        self.alert_agent = AlertAnalysisAgent(name="AlertAnalysisAgent", system_prompt="")
        self.vuln_agent = VulnHuntingAgent(name="VulnHuntingAgent", system_prompt="")
        self.report_agent = SecurityReportAgent(name="ReportGeneratorAgent", system_prompt="")

        self.tools = {
            "firewall": FirewallTool(),
            "edr": EDRTool(),
            "log_query": LogQueryTool()
        }

        self.rag = KnowledgeBase()

        self.shared_store = SharedDataStore()
        self.comm_protocol = None
        self.react_executor = ReActExecutor(self)

        logger.info("[SecurityOrchestrator] Initialized successfully")

    async def process_request(self, user_request: str) -> Dict[str, Any]:
        task_id = str(uuid.uuid4())
        logger.info(f"[Orchestrator] Processing request: {user_request}")

        intent = await self._parse_intent(user_request)
        logger.info(f"[Orchestrator] Parsed intent: {intent}")

        context = TaskContext(
            task_id=task_id,
            original_request=user_request,
            parsed_intent=intent.get("intent", ""),
            task_type=intent.get("task_type", "general_query"),
            status="running"
        )

        self.comm_protocol = AgentCommunicationProtocol(context)

        try:
            if intent.get("task_type") == "security_incident":
                result = await self._handle_security_incident(context)
            elif intent.get("task_type") == "daily_report":
                result = await self._handle_daily_report(context)
            elif intent.get("task_type") == "vuln_investigation":
                result = await self._handle_vuln_investigation(context)
            else:
                result = await self._handle_general_query(context, user_request)

            context.status = "completed"
            return {
                "success": True,
                "task_id": task_id,
                "result": result,
                "context": context
            }

        except Exception as e:
            logger.error(f"[Orchestrator] Error processing request: {e}")
            return {
                "success": False,
                "task_id": task_id,
                "error": str(e)
            }

    async def _parse_intent(self, user_request: str) -> Dict[str, Any]:
        prompt = f"""分析以下用户请求，确定任务类型和意图。
任务类型: security_incident, daily_report, vuln_investigation, general_query

用户请求: {user_request}

请用JSON格式返回: {{"task_type": "类型", "intent": "意图描述"}}"""

        response = await self.llm.agenerate([prompt])

        try:
            return json.loads(response.content)
        except:
            return {
                "task_type": "general_query",
                "intent": user_request
            }

    async def _handle_security_incident(self, context: TaskContext) -> Dict[str, Any]:
        context.current_phase = "alert_analysis"
        alert_result = await self._execute_alert_analysis(context)

        vuln_result = None
        remediation_result = None

        if alert_result.get("true_threats"):
            context.current_phase = "vuln_analysis"
            vuln_result = await self._execute_vuln_analysis(context, alert_result)

            context.current_phase = "remediation"
            remediation_result = await self._execute_remediation(context, vuln_result)

        context.current_phase = "report_generation"
        report = await self._execute_report_generation(context)

        return {
            "alert_analysis": alert_result,
            "vuln_analysis": vuln_result,
            "remediation": remediation_result,
            "final_report": report
        }

    async def _execute_alert_analysis(self, context: TaskContext) -> Dict[str, Any]:
        relevant_knowledge = self.rag.retrieve(
            query=context.original_request,
            k=5
        )

        result = self.alert_agent.chat(
            f"分析以下告警: {context.shared_context.get('alerts', [])}\n"
            f"参考知识: {relevant_knowledge}"
        )

        context.shared_context["alert_results"] = result
        context.agent_results["alert_analysis"] = result

        return {"data": result, "true_threats": []}

    async def _execute_vuln_analysis(
        self,
        context: TaskContext,
        alert_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        vulnerabilities = alert_result.get("vulnerabilities", [])

        vuln_results = []
        for vuln in vulnerabilities:
            result = self.vuln_agent.chat(
                f"分析漏洞: {vuln}\n"
                f"关联告警: {alert_result.get('true_threats', [])}"
            )
            vuln_results.append(result)

        context.shared_context["vulnerabilities"] = vuln_results
        context.agent_results["vuln_analysis"] = vuln_results

        return {"data": vuln_results}

    async def _execute_remediation(
        self,
        context: TaskContext,
        vuln_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        remediation_actions = []

        for vuln in vuln_results.get("data", []):
            if "attacker_ip" in vuln:
                firewall_result = self.tools["firewall"].block_ip(
                    ip_address=vuln["attacker_ip"],
                    reason=f"High severity vulnerability detected"
                )
                remediation_actions.append(firewall_result)

            if "affected_endpoint" in vuln:
                edr_result = self.tools["edr"].isolate_endpoint(
                    endpoint_id=vuln["affected_endpoint"],
                    reason="Vulnerability exploitation detected"
                )
                remediation_actions.append(edr_result)

        return {"actions": remediation_actions}

    async def _execute_report_generation(self, context: TaskContext) -> Dict[str, Any]:
        report_request = {
            "task_id": context.task_id,
            "alert_results": context.agent_results.get("alert_analysis"),
            "vuln_results": context.agent_results.get("vuln_analysis"),
            "raw_data": context.shared_context
        }

        report = self.report_agent.chat(
            f"生成安全事件报告: {report_request}"
        )

        return {"report": report}

    async def _handle_daily_report(self, context: TaskContext) -> Dict[str, Any]:
        context.current_phase = "data_collection"

        logs = self.tools["log_query"].search_events(
            keyword="security",
            time_range="24h"
        )

        context.shared_context["daily_logs"] = logs

        report = await self._execute_report_generation(context)

        return {"report": report}

    async def _handle_vuln_investigation(self, context: TaskContext) -> Dict[str, Any]:
        context.current_phase = "vuln_investigation"

        vuln_result = await self._execute_vuln_analysis(context, {})

        return {"vuln_analysis": vuln_result}

    async def _handle_general_query(
        self,
        context: TaskContext,
        user_request: str
    ) -> Dict[str, Any]:
        relevant_knowledge = self.rag.retrieve(
            query=user_request,
            k=5
        )

        prompt = f"""基于以下知识库内容回答用户问题。

知识库内容:
{chr(10).join(relevant_knowledge)}

用户问题: {user_request}"""

        response = await self.llm.agenerate([prompt])

        return {
            "answer": response.content,
            "sources": relevant_knowledge
        }