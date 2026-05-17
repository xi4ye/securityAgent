from typing import Dict, Any, TYPE_CHECKING
import time
from loguru import logger

if TYPE_CHECKING:
    from .core import SecurityOrchestrator


class ReActExecutor:
    def __init__(
        self,
        orchestrator: 'SecurityOrchestrator',
        max_iterations: int = 10
    ):
        self.orchestrator = orchestrator
        self.max_iterations = max_iterations

    async def execute(self, task_context) -> Dict[str, Any]:
        iteration = 0
        goal_achieved = False

        while iteration < self.max_iterations and not goal_achieved:
            iteration += 1
            logger.info(f"[ReAct] ===== Iteration {iteration} =====")

            thought = await self._think(task_context)
            task_context.thought_history.append(thought)
            logger.info(f"[ReAct] Thought: {thought}")

            action_result = await self._act(task_context, thought)
            task_context.action_history.append(thought)
            task_context.execution_history.append(action_result)

            observation = self._observe(action_result)
            task_context.observation_history.append(observation)
            logger.info(f"[ReAct] Observation: {observation}")

            goal_achieved = self._check_goal(task_context, observation)

        if goal_achieved:
            logger.info("[ReAct] Goal achieved!")
        else:
            logger.warning(f"[ReAct] Max iterations ({self.max_iterations}) reached")

        return {
            "success": goal_achieved,
            "iterations": iteration,
            "context": task_context
        }

    async def _think(self, context) -> str:
        prompt = f"""当前任务上下文:
- 任务类型: {context.task_type}
- 当前阶段: {context.current_phase}
- 已执行的操作: {len(context.execution_history)}

根据以上信息，分析当前状态，决定下一步应该执行什么操作。
请用一句话描述你的决策和理由。"""

        response = await self.orchestrator.llm.agenerate([prompt])
        return response.content

    async def _act(self, context, thought: str) -> Dict[str, Any]:
        action_type, target = self._parse_action(thought)

        if action_type == "agent":
            return await self._call_agent(context, target)
        elif action_type == "tool":
            return await self._call_tool(context, target)
        elif action_type == "report":
            return await self._generate_report(context)
        else:
            return {"error": f"Unknown action type: {action_type}"}

    def _parse_action(self, thought: str) -> tuple:
        thought_lower = thought.lower()

        if "alert" in thought_lower or "告警" in thought_lower:
            return ("agent", "alert_analysis")
        elif "vuln" in thought_lower or "漏洞" in thought_lower:
            return ("agent", "vuln_analysis")
        elif "report" in thought_lower or "报告" in thought_lower:
            return ("report", None)
        elif "firewall" in thought_lower or "封禁" in thought_lower:
            return ("tool", "firewall")
        elif "edr" in thought_lower or "隔离" in thought_lower:
            return ("tool", "edr")
        else:
            return ("report", None)

    async def _call_agent(self, context, target: str) -> Dict[str, Any]:
        if target == "alert_analysis":
            return await self.orchestrator._execute_alert_analysis(context)
        elif target == "vuln_analysis":
            return await self.orchestrator._execute_vuln_analysis(context, {})
        return {"error": f"Unknown agent: {target}"}

    async def _call_tool(self, context, target: str) -> Dict[str, Any]:
        if target in self.orchestrator.tools:
            return self.orchestrator.tools[target].execute({})
        return {"error": f"Unknown tool: {target}"}

    async def _generate_report(self, context) -> Dict[str, Any]:
        return await self.orchestrator._execute_report_generation(context)

    def _observe(self, action_result: Dict[str, Any]) -> str:
        if "error" in action_result:
            return f"执行失败: {action_result['error']}"
        if "data" in action_result:
            return f"执行成功，获得数据: {type(action_result['data'])}"
        return "执行完成"

    def _check_goal(self, context, observation: str) -> bool:
        if context.current_phase == "completed":
            return True
        if len(context.execution_history) >= self.max_iterations:
            return True
        return False