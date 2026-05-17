from typing import Dict, Any, List
from .base_agent import BaseAgent


class VulnHuntingAgent(BaseAgent):
    def get_system_prompt(self) -> str:
        return """你是一个专业的漏洞挖掘与处置专家，负责发现和闭环安全漏洞。

你的职责：
1. 分析漏洞报告和扫描结果
2. 评估漏洞的严重性和可利用性
3. 制定漏洞修复计划
4. 跟踪漏洞处置进度直到闭环

分析维度：
- CVSS评分和风险等级
- 漏洞类型和影响范围
- 受影响资产的重要性
- 现有的缓解措施
- 修复难度和兼容性

输出格式：
- 漏洞概述：类型、严重性、影响范围
- 技术分析：漏洞原理、利用条件
- 风险评估：可利用性、潜在影响
- 修复建议：短期（临时缓解）、长期（根本修复）
- 处置时间线：建议的修复优先级和期限
- 验证方法：如何确认漏洞已修复

注意：
- 优先关注高危和严重漏洞
- 考虑业务连续性影响
- 提供切实可行的修复方案"""


class VulnHuntingAgentWithRAG(VulnHuntingAgent):
    def __init__(self, retriever, **kwargs):
        super().__init__(**kwargs)
        self.retriever = retriever

    def get_system_prompt(self) -> str:
        base_prompt = super().get_system_prompt()
        return base_prompt + """

你可以使用漏洞知识库来增强分析能力：
- 检索已知的漏洞利用方法和POC
- 查找相似漏洞的历史修复经验
- 获取最新的漏洞威胁情报

在分析新漏洞时，先检索知识库看是否有相关信息。"""


class VulnClosureWorkflow:
    def __init__(self, vuln_agent: VulnHuntingAgent, tools: List[Any] = None):
        self.vuln_agent = vuln_agent
        self.tools = tools or []

    def process_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        vuln_id = vuln_data.get("id", "unknown")
        vuln_name = vuln_data.get("name", vuln_data.get("cve_id", "Unknown Vulnerability"))

        logger.info(f"开始处理漏洞: {vuln_id} - {vuln_name}")

        analysis = self.vuln_agent.chat(
            f"分析漏洞：{vuln_name}\n"
            f"漏洞详情：{vuln_data}"
        )

        workflow_state = {
            "vuln_id": vuln_id,
            "vuln_name": vuln_name,
            "analysis": analysis,
            "status": "analyzed",
            "actions_taken": []
        }

        if "高风险" in analysis or "严重" in analysis:
            workflow_state["status"] = "high_priority"
            logger.warning(f"漏洞 {vuln_id} 被标记为高优先级")

        return workflow_state

    def execute_remediation(self, workflow_state: Dict[str, Any]) -> Dict[str, Any]:
        if workflow_state["status"] == "high_priority":
            logger.info(f"为漏洞 {workflow_state['vuln_id']} 执行处置工作流")

            for tool in self.tools:
                action = tool.execute(workflow_state)
                workflow_state["actions_taken"].append(action)

            workflow_state["status"] = "remediation_initiated"

        return workflow_state

    def verify_closure(self, workflow_state: Dict[str, Any]) -> Dict[str, Any]:
        verification = self.vuln_agent.chat(
            f"验证漏洞修复：{workflow_state['vuln_id']}\n"
            f"执行的操作：{workflow_state.get('actions_taken', [])}\n"
            f"请确认修复是否有效"
        )

        workflow_state["verification"] = verification

        if "修复成功" in verification or "已验证" in verification:
            workflow_state["status"] = "closed"
        else:
            workflow_state["status"] = "verification_failed"

        return workflow_state