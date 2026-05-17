# SecurityOrchestrator 详细设计方案

**版本**: v1.0
**日期**: 2026-05-11
**状态**: 设计中

---

## 1. 核心定位

SecurityOrchestrator 是整个安全智能体系统的 **中央协调器**，负责：

1. **理解用户意图** - 解析自然语言指令
2. **规划任务流程** - 确定需要调用哪些Agent和工具
3. **协调Agent协作** - 管理Agent之间的信息流转
4. **执行安全动作** - 调用防火墙、EDR等工具
5. **实现ReAct循环** - 观测结果→反馈→重新规划
6. **生成最终报告** - 汇总所有分析结果

---

## 2. 架构设计

### 2.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                         用户界面层                                │
│                    （命令行 / API / 未来Web）                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SecurityOrchestrator                          │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                    意图理解层                              │  │
│  │  • 解析用户指令                                            │  │
│  │  • 识别任务类型                                            │  │
│  │  • 提取关键参数                                            │  │
│  └─────────────────────────────────────────────────────────┘  │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                    任务规划层                              │  │
│  │  • 创建执行计划                                            │  │
│  │  • 确定Agent调用顺序                                        │  │
│  │  • 管理依赖关系                                            │  │
│  └─────────────────────────────────────────────────────────┘  │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                    ReAct执行层                            │  │
│  │                                                          │  │
│  │    ┌──────────┐     ┌──────────┐     ┌──────────┐       │  │
│  │    │  Thought │────▶│  Action │────▶│ Observer │       │  │
│  │    └──────────┘     └──────────┘     └──────────┘       │  │
│  │          ▲                                   │           │  │
│  │          └───────────────────────────────────┘           │  │
│  │                                                          │  │
│  │  • Thought: 分析当前情况，决定下一步                       │  │
│  │  • Action: 执行Agent或Tool                                │  │
│  │  • Observer: 观测结果，评估是否达成目标                    │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   Agent层       │ │   Tool层        │ │   RAG层         │
├─────────────────┤├─────────────────┤├─────────────────┤
│ AlertAnalysis   │ │ FirewallTool    │ │ 监管政策库      │
│ VulnHunting     │ │ EDRTool         │ │ 漏洞知识库      │
│ ReportGenerator │ │ LogQueryTool    │ │ ATT&CK图谱     │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

---

## 3. 数据结构设计

### 3.1 消息协议

```python
from typing import Dict, Any, List, Optional
from enum import Enum
from pydantic import BaseModel


class MessageType(str, Enum):
    USER_COMMAND = "user_command"           # 用户指令
    AGENT_REQUEST = "agent_request"         # Agent请求
    AGENT_RESPONSE = "agent_response"       # Agent响应
    TOOL_REQUEST = "tool_request"           # 工具请求
    TOOL_RESPONSE = "tool_response"         # 工具响应
    ORCHESTRATOR_COMMAND = "orchestrator_command"  # 编排器命令
    FINAL_REPORT = "final_report"           # 最终报告


class AgentMessage(BaseModel):
    """Agent间通信消息格式"""
    msg_id: str                              # 消息唯一ID
    msg_type: MessageType                    # 消息类型
    sender: str                              # 发送者名称
    receiver: Optional[str] = None           # 接收者名称（None表示广播）
    content: Dict[str, Any]                  # 消息内容
    context: Dict[str, Any] = {}            # 上下文信息
    timestamp: float                         # 时间戳

    class Config:
        use_enum_values = True


# 消息内容格式示例
class AlertAnalysisRequest(BaseModel):
    """告警分析请求"""
    task_id: str
    alerts: List[Dict[str, Any]]
    context: Dict[str, Any] = {}


class AlertAnalysisResponse(BaseModel):
    """告警分析响应"""
    task_id: str
    true_threats: List[Dict[str, Any]]
    false_positives: List[Dict[str, Any]]
    needs_investigation: List[Dict[str, Any]]
    summary: Dict[str, Any]
    recommended_actions: List[str] = []


class VulnAnalysisRequest(BaseModel):
    """漏洞分析请求"""
    task_id: str
    vulnerability: Dict[str, Any]
    related_alerts: List[Dict[str, Any]] = []


class VulnAnalysisResponse(BaseModel):
    """漏洞分析响应"""
    task_id: str
    analysis: str
    severity: str  # low, medium, high, critical
    risk_assessment: Dict[str, Any]
    remediation_plan: Dict[str, Any]
    recommended_actions: List[str] = []


class ReportGenerationRequest(BaseModel):
    """报告生成请求"""
    task_id: str
    alert_results: Optional[AlertAnalysisResponse] = None
    vuln_results: Optional[VulnAnalysisResponse] = None
    raw_data: Dict[str, Any] = {}
    report_type: str = "incident"  # incident, daily, weekly


class ReportGenerationResponse(BaseModel):
    """报告生成响应"""
    task_id: str
    report: str
    summary: str
    key_findings: List[str] = []
    recommended_actions: List[str] = []
```

### 3.2 任务上下文

```python
class TaskContext(BaseModel):
    """任务执行上下文"""
    task_id: str
    original_request: str                     # 用户原始请求
    parsed_intent: str                        # 解析后的意图
    task_type: str                            # 任务类型
    status: str = "pending"                   # pending, running, completed, failed

    # 执行历史
    execution_history: List[Dict[str, Any]] = []

    # Agent结果存储
    agent_results: Dict[str, Any] = {}

    # 共享上下文（供所有Agent访问）
    shared_context: Dict[str, Any] = {
        "alerts": [],
        "vulnerabilities": [],
        "ioc": [],  # Indicators of Compromise
        "affected_assets": [],
        "timeline": []
    }

    # 当前执行状态
    current_phase: str = "init"
    next_actions: List[str] = []

    # ReAct状态
    thought_history: List[str] = []
    action_history: List[str] = []
    observation_history: List[str] = []
```

---

## 4. Agent通信机制

### 4.1 通信协议

```python
class AgentCommunicationProtocol:
    """
    Agent间通信协议
    支持三种通信模式：
    1. Request-Response: 请求-响应模式
    2. Event-Driven: 事件驱动模式
    3. Shared-State: 共享状态模式
    """

    def __init__(self, context: TaskContext):
        self.context = context
        self.message_queue: List[AgentMessage] = []

    async def send_message(
        self,
        receiver: str,
        msg_type: MessageType,
        content: Dict[str, Any]
    ) -> AgentMessage:
        """发送消息给指定Agent"""
        msg = AgentMessage(
            msg_id=self._generate_msg_id(),
            msg_type=msg_type,
            sender="orchestrator",
            receiver=receiver,
            content=content,
            context=self.context.shared_context,
            timestamp=time.time()
        )

        self.message_queue.append(msg)
        logger.info(f"[Orchestrator] → {receiver}: {msg_type}")

        return msg

    async def receive_message(self, sender: str) -> Optional[AgentMessage]:
        """接收来自Agent的消息"""
        for msg in self.message_queue:
            if msg.sender == sender:
                self.message_queue.remove(msg)
                logger.info(f"[Orchestrator] ← {sender}: {msg.msg_type}")
                return msg
        return None

    async def broadcast(
        self,
        msg_type: MessageType,
        content: Dict[str, Any]
    ) -> List[AgentMessage]:
        """广播消息给所有Agent"""
        messages = []
        for agent_name in ["AlertAnalysisAgent", "VulnHuntingAgent", "ReportGeneratorAgent"]:
            msg = await self.send_message(agent_name, msg_type, content)
            messages.append(msg)
        return messages
```

### 4.2 共享数据存储

```python
class SharedDataStore:
    """
    共享数据存储
    所有Agent共享的数据存储在这里
    """

    def __init__(self):
        self._store: Dict[str, Any] = {}

    def set(self, key: str, value: Any):
        """设置共享数据"""
        self._store[key] = value
        logger.debug(f"[SharedStore] {key} = {type(value)}")

    def get(self, key: str, default: Any = None) -> Any:
        """获取共享数据"""
        return self._store.get(key, default)

    def append(self, key: str, value: Any):
        """向列表类型数据追加内容"""
        if key not in self._store:
            self._store[key] = []
        if isinstance(self._store[key], list):
            self._store[key].append(value)

    def get_all(self) -> Dict[str, Any]:
        """获取所有共享数据"""
        return self._store.copy()

    def clear(self):
        """清空共享数据"""
        self._store.clear()
```

---

## 5. ReAct工作流实现

### 5.1 ReAct循环核心

```python
from typing import Callable, List, Dict, Any, Optional
import time


class ReActExecutor:
    """
    ReAct (Reasoning + Acting) 执行器
    实现 思考→行动→观测 的循环
    """

    def __init__(
        self,
        orchestrator: 'SecurityOrchestrator',
        max_iterations: int = 10
    ):
        self.orchestrator = orchestrator
        self.max_iterations = max_iterations

    async def execute(self, task_context: TaskContext) -> Dict[str, Any]:
        """
        执行ReAct循环

        循环流程:
        1. Think: 分析当前状态，决定下一步行动
        2. Action: 执行Agent调用或Tool调用
        3. Observe: 观测执行结果
        4. 判断是否达成目标或达到最大迭代次数
        """

        iteration = 0
        goal_achieved = False

        while iteration < self.max_iterations and not goal_achieved:
            iteration += 1
            logger.info(f"[ReAct] ===== Iteration {iteration} =====")

            # 1. Think - 分析当前状态，决定行动
            thought = await self._think(task_context)
            task_context.thought_history.append(thought)
            logger.info(f"[ReAct] Thought: {thought}")

            # 2. Action - 执行行动
            action_result = await self._act(task_context, thought)
            task_context.action_history.append(thought)
            task_context.execution_history.append(action_result)

            # 3. Observe - 观测结果
            observation = self._observe(action_result)
            task_context.observation_history.append(observation)
            logger.info(f"[ReAct] Observation: {observation}")

            # 4. Check Goal - 检查是否达成目标
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

    async def _think(self, context: TaskContext) -> str:
        """思考：分析当前状态，决定下一步行动"""
        prompt = f"""当前任务上下文:
- 任务类型: {context.task_type}
- 当前阶段: {context.current_phase}
- 已执行的操作: {len(context.execution_history)}
- 共享数据状态: {self._summarize_shared_data(context)}

根据以上信息，分析当前状态，决定下一步应该：
1. 调用哪个Agent（AlertAnalysis / VulnHunting / ReportGenerator）
2. 调用哪个Tool（Firewall / EDR / LogQuery）
3. 生成最终报告

请用一句话描述你的决策和理由。"""

        response = await self.orchestrator.llm.agenerate([prompt])
        return response.content

    async def _act(
        self,
        context: TaskContext,
        thought: str
    ) -> Dict[str, Any]:
        """行动：根据思考结果执行操作"""
        # 解析thought中的行动指令
        action_type, target = self._parse_action(thought)

        if action_type == "agent":
            return await self._call_agent(context, target)
        elif action_type == "tool":
            return await self._call_tool(context, target)
        elif action_type == "report":
            return await self._generate_report(context)
        else:
            return {"error": f"Unknown action type: {action_type}"}

    def _observe(self, action_result: Dict[str, Any]) -> str:
        """观测：分析行动结果"""
        if "error" in action_result:
            return f"执行失败: {action_result['error']}"

        if "data" in action_result:
            return f"执行成功，获得数据: {type(action_result['data'])}"

        return "执行完成"

    def _check_goal(self, context: TaskContext, observation: str) -> bool:
        """检查目标是否达成"""
        # 检查是否生成了最终报告
        if context.current_phase == "completed":
            return True

        # 检查是否达到了最大迭代次数但没有完成
        if len(context.execution_history) >= self.max_iterations:
            return True

        return False

    def _summarize_shared_data(self, context: TaskContext) -> str:
        """总结共享数据状态"""
        return f"""
- 已分析告警数: {len(context.shared_context.get('alerts', []))}
- 已发现漏洞数: {len(context.shared_context.get('vulnerabilities', []))}
- IoC数量: {len(context.shared_context.get('ioc', []))}
- 受影响资产: {len(context.shared_context.get('affected_assets', []))}
"""
```

---

## 6. SecurityOrchestrator 完整实现

### 6.1 核心类

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import uuid
import time
from loguru import logger

from agents import (
    AlertAnalysisAgent,
    VulnHuntingAgent,
    SecurityReportAgent
)
from tools import FirewallTool, EDRTool, LogQueryTool
from rag import KnowledgeBase
from config.settings import *


class SecurityOrchestrator:
    """
    安全智能体编排器
    负责协调所有Agent和Tool，实现自动化安全运营
    """

    def __init__(self):
        # 初始化LLM
        from langchain_community.chat_models import ChatDeepSeek
        self.llm = ChatDeepSeek(
            model=DEEPSEEK_MODEL,
            api_key=DEEPSEEK_API_KEY,
            base_url=DEEPSEEK_API_BASE,
            temperature=0.7
        )

        # 初始化Agent
        self.alert_agent = AlertAnalysisAgent(name="AlertAnalysisAgent")
        self.vuln_agent = VulnHuntingAgent(name="VulnHuntingAgent")
        self.report_agent = SecurityReportAgent(name="ReportGeneratorAgent")

        # 初始化Tools
        self.tools = {
            "firewall": FirewallTool(),
            "edr": EDRTool(),
            "log_query": LogQueryTool()
        }

        # 初始化RAG
        self.rag = KnowledgeBase()

        # 初始化通信协议
        self.shared_store = SharedDataStore()
        self.comm_protocol = None  # 运行时创建

        # 初始化ReAct执行器
        self.react_executor = ReActExecutor(self)

        logger.info("[SecurityOrchestrator] Initialized successfully")

    async def process_request(self, user_request: str) -> Dict[str, Any]:
        """
        处理用户请求的主入口

        Args:
            user_request: 用户的自然语言请求

        Returns:
            处理结果字典
        """
        task_id = str(uuid.uuid4())
        logger.info(f"[Orchestrator] Processing request: {user_request}")

        # 1. 解析用户意图
        intent = await self._parse_intent(user_request)
        logger.info(f"[Orchestrator] Parsed intent: {intent}")

        # 2. 创建任务上下文
        context = TaskContext(
            task_id=task_id,
            original_request=user_request,
            parsed_intent=intent.get("intent"),
            task_type=intent.get("task_type"),
            status="running"
        )

        # 3. 初始化通信协议
        self.comm_protocol = AgentCommunicationProtocol(context)

        # 4. 执行任务（使用ReAct循环）
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
        """解析用户意图"""
        prompt = f"""分析以下用户请求，确定：
1. 任务类型（security_incident / daily_report / vuln_investigation / general_query）
2. 关键意图

用户请求: {user_request}

请用JSON格式返回，格式如下：
{{"task_type": "类型", "intent": "意图描述", "parameters": {{}}}}"""

        response = await self.llm.agenerate([prompt])

        try:
            import json
            return json.loads(response.content)
        except:
            return {
                "task_type": "general_query",
                "intent": user_request,
                "parameters": {}
            }

    async def _handle_security_incident(
        self,
        context: TaskContext
    ) -> Dict[str, Any]:
        """处理安全事件"""

        # Step 1: 告警分析
        context.current_phase = "alert_analysis"
        alert_result = await self._execute_alert_analysis(context)

        # Step 2: 如果发现真实威胁，进行漏洞分析
        if alert_result.get("true_threats"):
            context.current_phase = "vuln_analysis"
            vuln_result = await self._execute_vuln_analysis(context, alert_result)

            # Step 3: 执行自动处置
            context.current_phase = "remediation"
            remediation_result = await self._execute_remediation(context, vuln_result)

        # Step 4: 生成报告
        context.current_phase = "report_generation"
        report = await self._execute_report_generation(context)

        return {
            "alert_analysis": alert_result,
            "vuln_analysis": vuln_result if alert_result.get("true_threats") else None,
            "remediation": remediation_result if alert_result.get("true_threats") else None,
            "final_report": report
        }

    async def _execute_alert_analysis(
        self,
        context: TaskContext
    ) -> Dict[str, Any]:
        """执行告警分析"""
        # 从RAG获取相关知识
        relevant_knowledge = self.rag.retrieve(
            query=context.original_request,
            k=5
        )

        # 调用AlertAnalysisAgent
        alert_request = AlertAnalysisRequest(
            task_id=context.task_id,
            alerts=context.shared_context.get("alerts", []),
            context={"knowledge": relevant_knowledge}
        )

        result = await self.alert_agent.ainvoke(
            alert_request.dict()
        )

        # 更新共享数据
        context.shared_context["alert_results"] = result
        context.agent_results["alert_analysis"] = result

        return result

    async def _execute_vuln_analysis(
        self,
        context: TaskContext,
        alert_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """执行漏洞分析"""
        # 获取关联的漏洞信息
        vulnerabilities = self._extract_vulnerabilities(alert_result)

        vuln_results = []
        for vuln in vulnerabilities:
            vuln_request = VulnAnalysisRequest(
                task_id=context.task_id,
                vulnerability=vuln,
                related_alerts=alert_result.get("true_threats", [])
            )

            result = await self.vuln_agent.ainvoke(
                vuln_request.dict()
            )
            vuln_results.append(result)

        # 更新共享数据
        context.shared_context["vulnerabilities"] = vuln_results
        context.agent_results["vuln_analysis"] = vuln_results

        return vuln_results

    async def _execute_remediation(
        self,
        context: TaskContext,
        vuln_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """执行安全处置"""
        remediation_actions = []

        for vuln in vuln_results:
            if vuln.get("severity") in ["high", "critical"]:
                # 自动封禁IP
                if "attacker_ip" in vuln:
                    firewall_result = self.tools["firewall"].block_ip(
                        ip_address=vuln["attacker_ip"],
                        reason=f"High severity vulnerability: {vuln.get('cve_id')}"
                    )
                    remediation_actions.append({
                        "action": "block_ip",
                        "target": vuln["attacker_ip"],
                        "result": firewall_result
                    })

                # 隔离端点
                if "affected_endpoint" in vuln:
                    edr_result = self.tools["edr"].isolate_endpoint(
                        endpoint_id=vuln["affected_endpoint"],
                        reason=f"Vulnerability exploitation detected"
                    )
                    remediation_actions.append({
                        "action": "isolate_endpoint",
                        "target": vuln["affected_endpoint"],
                        "result": edr_result
                    })

        return remediation_actions

    async def _execute_report_generation(
        self,
        context: TaskContext
    ) -> Dict[str, Any]:
        """生成安全报告"""
        report_request = ReportGenerationRequest(
            task_id=context.task_id,
            alert_results=context.agent_results.get("alert_analysis"),
            vuln_results=context.agent_results.get("vuln_analysis"),
            raw_data=context.shared_context,
            report_type="incident"
        )

        report = await self.report_agent.ainvoke(
            report_request.dict()
        )

        return report

    async def _handle_daily_report(
        self,
        context: TaskContext
    ) -> Dict[str, Any]:
        """处理日报请求"""
        context.current_phase = "data_collection"

        # 查询最近24小时日志
        logs = self.tools["log_query"].search_events(
            keyword="security",
            time_range="24h"
        )

        context.shared_context["daily_logs"] = logs

        # 生成报告
        report_request = ReportGenerationRequest(
            task_id=context.task_id,
            raw_data=context.shared_context,
            report_type="daily"
        )

        report = await self.report_agent.ainvoke(
            report_request.dict()
        )

        return {"report": report}

    async def _handle_vuln_investigation(
        self,
        context: TaskContext
    ) -> Dict[str, Any]:
        """处理漏洞调查"""
        context.current_phase = "vuln_investigation"

        vuln_result = await self._execute_vuln_analysis(context, {})

        return {"vuln_analysis": vuln_result}

    async def _handle_general_query(
        self,
        context: TaskContext,
        user_request: str
    ) -> Dict[str, Any]:
        """处理通用查询"""
        # 从RAG获取相关知识
        relevant_knowledge = self.rag.retrieve(
            query=user_request,
            k=5
        )

        # 使用LLM直接回答
        prompt = f"""基于以下知识库内容，回答用户问题。如果知识库中没有相关信息，请说明。

知识库内容:
{chr(10).join(relevant_knowledge)}

用户问题: {user_request}"""

        response = await self.llm.agenerate([prompt])

        return {
            "answer": response.content,
            "sources": relevant_knowledge
        }
```

---

## 7. API接口设计

### 7.1 FastAPI接口

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any

app = FastAPI(title="Security Orchestrator API")

orchestrator = SecurityOrchestrator()


class UserRequest(BaseModel):
    message: str


@app.post("/api/orchestrate")
async def orchestrate(request: UserRequest) -> Dict[str, Any]:
    """统一的编排入口"""
    return await orchestrator.process_request(request.message)


@app.post("/api/alert/analyze")
async def analyze_alerts(alerts: list) -> Dict[str, Any]:
    """单独调用告警分析"""
    context = TaskContext(
        task_id="standalone-alert",
        original_request="Alert analysis",
        task_type="alert_analysis"
    )
    context.shared_context["alerts"] = alerts
    return await orchestrator._execute_alert_analysis(context)


@app.post("/api/vuln/analyze")
async def analyze_vulnerabilities(vulnerability: dict) -> Dict[str, Any]:
    """单独调用漏洞分析"""
    context = TaskContext(
        task_id="standalone-vuln",
        original_request="Vulnerability analysis",
        task_type="vuln_analysis"
    )
    return await orchestrator._execute_vuln_analysis(context, {"vulnerability": vulnerability})


@app.post("/api/report/generate")
async def generate_report(report_type: str = "incident") -> Dict[str, Any]:
    """单独调用报告生成"""
    context = TaskContext(
        task_id="standalone-report",
        original_request="Report generation",
        task_type="report_generation"
    )
    return await orchestrator._execute_report_generation(context)
```

---

## 8. 执行流程图

```
用户请求
    │
    ▼
意图解析
    │
    ├─▶ 安全事件 ──▶ 告警分析 ──▶ [发现威胁] ──▶ 漏洞分析
    │                                      │
    │                                      ▼
    │                                 自动处置
    │                                 (封禁/隔离)
    │                                      │
    │                                      ▼
    │                                 生成报告
    │                                      │
    ├─▶ 日报请求 ──▶ 数据收集 ──▶ 报告生成
    │                                      │
    ├─▶ 漏洞调查 ──▶ 漏洞分析 ──▶ 返回结果
    │                                      │
    └─▶ 通用查询 ──▶ RAG检索 ──▶ 回答问题
```

---

## 9. 依赖关系图

```
┌─────────────────────────────────────────────────────────────────┐
│                    SecurityOrchestrator                          │
│                    (中央编排器)                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ AlertAnalysis   │  │ VulnHunting     │  │ ReportGenerator │
│ Agent          │  │ Agent           │  │ Agent           │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ FirewallTool    │  │ EDRTool         │  │ LogQueryTool   │
└─────────────────┘  └─────────────────┘  └─────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  RAG Knowledge   │
                    │  Base (ChromaDB) │
                    └─────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ 监管政策库      │  │ 漏洞知识库      │  │ ATT&CK图谱     │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## 10. 下一步开发任务

### Task 1: 核心骨架实现
- [ ] 实现 `SharedDataStore`
- [ ] 实现 `AgentCommunicationProtocol`
- [ ] 实现 `TaskContext`
- [ ] 实现 `SecurityOrchestrator` 主类

### Task 2: Agent完善
- [ ] 完善 `AlertAnalysisAgent` prompt
- [ ] 完善 `VulnHuntingAgent` prompt
- [ ] 完善 `ReportGeneratorAgent` prompt

### Task 3: ReAct实现
- [ ] 实现 `ReActExecutor`
- [ ] 实现 `_think` 方法
- [ ] 实现 `_act` 方法
- [ ] 实现 `_observe` 方法

### Task 4: 工具集成
- [ ] 实现 `FirewallTool` 真实API对接
- [ ] 实现 `EDRTool` 真实API对接
- [ ] 实现 `LogQueryTool` 真实API对接

### Task 5: RAG完善
- [ ] 收集安全知识库内容
- [ ] 实现向量化导入
- [ ] 优化检索算法

### Task 6: 测试与集成
- [ ] 单元测试
- [ ] 集成测试
- [ ] 端到端测试

---

## 11. 文件结构更新

```
security-agent/
├── agents/                      # Agent层
│   ├── base_agent.py
│   ├── security_report_agent.py
│   ├── alert_analysis_agent.py
│   └── vuln_hunting_agent.py
├── orchestrator/                # 新增：编排器层
│   ├── __init__.py
│   ├── core.py                  # SecurityOrchestrator主类
│   ├── context.py                # TaskContext定义
│   ├── communication.py         # Agent通信协议
│   ├── react.py                 # ReAct执行器
│   └── intent_parser.py         # 意图解析
├── rag/                         # RAG层
│   └── knowledge_base.py
├── tools/                       # 工具层
│   └── firewall_tool.py
├── api/                         # API层
│   └── main.py
├── config/
│   └── settings.py
└── requirements.txt
```

---

## 12. 总结

SecurityOrchestrator 是整个系统的核心，负责：

1. **统一入口** - 接收用户请求，协调所有Agent
2. **智能规划** - 解析意图，规划执行流程
3. **ReAct执行** - 实现思考→行动→观测的智能循环
4. **Agent协作** - 管理Agent间的信息流转
5. **工具调用** - 自动化执行安全处置
6. **结果汇总** - 生成统一的安全报告

**关键设计原则**:
- 松耦合：Agent独立，又能协作
- 可扩展：容易添加新的Agent或Tool
- 可追踪：完整的执行历史
- 智能化：ReAct实现自主决策