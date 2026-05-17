# 代码集成方案 - Agent协作系统

**版本**: v1.0
**日期**: 2026-05-11
**状态**: 设计中

---

## 1. 核心问题分析

### 1.1 为什么集成困难？

```
传统开发：模块A → 模块B → 模块C
         接口清晰，可以独立测试

Agent开发：AlertAgent → VulnAgent → ReportAgent
          输出是自然语言，格式不固定
          每个Agent的输出是下一个的输入
          LLM输出不稳定，可能格式不一致
```

### 1.2 集成风险

| 风险 | 描述 | 影响 |
|------|------|------|
| 接口不一致 | Agent输出格式不统一 | 下游无法解析 |
| 依赖耦合 | 硬编码Agent间依赖 | 测试困难 |
| LLM不稳定 | 同样输入，不同输出 | 回归测试失败 |
| 幻觉问题 | Agent输出错误信息 | 整个链路失败 |

---

## 2. 统一接口规范

### 2.1 核心原则

```
每个Agent必须：
1. 接收结构化的输入（JSON/Pydantic）
2. 输出结构化的结果（JSON/Pydantic）
3. 不依赖其他Agent的实现细节
4. 可以单独测试
```

### 2.2 标准输入输出格式

```python
# ========== 标准输入格式 ==========
class AgentInput(BaseModel):
    task_id: str                           # 任务ID（用于追踪）
    content: Dict[str, Any]               # 具体输入内容
    context: Optional[Dict[str, Any]] = {} # 共享上下文
    constraints: Optional[Dict[str, Any]] = {} # 约束条件


# ========== 标准输出格式 ==========
class AgentOutput(BaseModel):
    task_id: str                           # 任务ID
    status: str                            # success / failed / partial
    result: Dict[str, Any]                # 具体输出结果
    artifacts: List[str] = []             # 产物列表（报告ID等）
    metadata: Dict[str, Any] = {}         # 元信息（耗时、token等）
    error: Optional[str] = None            # 错误信息（如果失败）
    next_hints: List[str] = []            # 给下游Agent的提示


# ========== 统一的Agent基类 ==========
class StandardizedAgent(ABC):
    """
    所有Agent必须继承此基类
    确保接口统一
    """

    @abstractmethod
    def get_input_schema(self) -> Type[BaseModel]:
        """返回输入数据的schema"""
        pass

    @abstractmethod
    def get_output_schema(self) -> Type[BaseModel]:
        """返回输出数据的schema"""
        pass

    @abstractmethod
    async def execute(self, task_id: str, input_data: Dict[str, Any]) -> AgentOutput:
        """
        标准化执行入口
        1. 验证输入格式
        2.执行业务逻辑
        3. 标准化输出格式
        """
        pass
```

### 2.3 具体Agent的输入输出定义

#### AlertAnalysisAgent

```python
# 输入
class AlertAnalysisInput(BaseModel):
    alerts: List[Dict[str, Any]]  # 告警列表
    time_range: str = "24h"       # 时间范围
    context: Optional[Dict] = {}  # 上下文

# 输出
class AlertAnalysisOutput(BaseModel):
    total_analyzed: int
    true_threats: List[ThreatInfo]
    false_positives: List[FalsePositiveInfo]
    needs_investigation: List[InvestigationInfo]
    confidence: float
    recommended_actions: List[str]
    iocs: List[IOC]  # Indicators of Compromise
    affected_assets: List[str]
```

#### VulnHuntingAgent

```python
# 输入
class VulnHuntingInput(BaseModel):
    vulnerabilities: List[Dict[str, Any]]  # 漏洞列表
    related_iocs: List[IOC] = []            # 关联IoC
    related_alerts: List[Alert] = []         # 关联告警
    context: Optional[Dict] = {}

# 输出
class VulnHuntingOutput(BaseModel):
    total_analyzed: int
    vulnerabilities: List[VulnDetail]
    high_risk_count: int
    remediation_plans: List[RemediationPlan]
    recommended_actions: List[Action]
```

#### ReportGeneratorAgent

```python
# 输入
class ReportGenerationInput(BaseModel):
    report_type: str  # incident / daily / weekly / custom
    alert_results: Optional[AlertAnalysisOutput] = None
    vuln_results: Optional[VulnHuntingOutput] = None
    raw_data: Dict[str, Any] = {}
    template: Optional[str] = None

# 输出
class ReportGenerationOutput(BaseModel):
    report_id: str
    report_content: str
    summary: str
    key_findings: List[str]
    recommendations: List[str]
    confidence: float
```

---

## 3. 测试框架设计

### 3.1 测试分层

```
┌─────────────────────────────────────┐
│      E2E 测试（端到端）               │
│   测试完整工作流                     │
│   测试所有Agent串联                   │
└─────────────────────────────────────┘
              ▲
              │ 集成测试
              ▼
┌─────────────────────────────────────┐
│      Mock 测试（模拟下游）            │
│   测试单个Agent                     │
│   Mock其他Agent输出                  │
└─────────────────────────────────────┘
              ▲
              │ 单元测试
              ▼
┌─────────────────────────────────────┐
│      接口测试（Contract）             │
│   验证输入输出格式                   │
│   验证数据契约                       │
└─────────────────────────────────────┘
```

### 3.2 测试框架实现

```python
# tests/conftest.py
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


# tests/test_alert_agent.py
class TestAlertAnalysisAgent:
    """AlertAnalysisAgent单元测试"""

    @pytest.fixture
    def agent(self):
        from agents.alert_analysis_agent import AlertAnalysisAgent
        return AlertAnalysisAgent(name="TestAlertAgent")

    @pytest.mark.asyncio
    async def test_valid_input(self, agent, mock_alert_output):
        """测试有效输入"""
        result = await agent.execute(
            task_id="test-001",
            input_data={
                "alerts": [{"id": "alert-1", "type": "login_failed"}],
                "time_range": "1h"
            }
        )

        assert result.status == "success"
        assert "result" in result.result

    @pytest.mark.asyncio
    async def test_output_schema(self, agent):
        """测试输出格式符合schema"""
        result = await agent.execute(
            task_id="test-001",
            input_data={"alerts": [], "time_range": "1h"}
        )

        # 验证输出字段
        assert hasattr(result, 'task_id')
        assert hasattr(result, 'status')
        assert hasattr(result, 'result')
        assert result.status in ["success", "failed", "partial"]


# tests/test_vuln_agent.py
class TestVulnHuntingAgent:
    """VulnHuntingAgent单元测试"""

    @pytest.fixture
    def agent(self):
        from agents.vuln_hunting_agent import VulnHuntingAgent
        return VulnHuntingAgent(name="TestVulnAgent")

    @pytest.mark.asyncio
    async def test_with_mock_input(self, agent, mock_vuln_output):
        """使用Mock输入测试"""
        result = await agent.execute(
            task_id="test-002",
            input_data={
                "vulnerabilities": [{"cve_id": "CVE-2024-1234"}]
            }
        )

        assert result.status == "success"


# tests/test_integration.py
class TestAgentIntegration:
    """集成测试 - 测试Agent串联"""

    @pytest.fixture
    def orchestrator(self):
        from orchestrator.core import SecurityOrchestrator
        return SecurityOrchestrator()

    @pytest.mark.asyncio
    async def test_security_incident_workflow(self, orchestrator):
        """测试完整的安全事件工作流"""

        # Step 1: 模拟用户输入
        user_request = "分析最近24小时的告警，生成安全报告"

        # Step 2: 执行编排器
        result = await orchestrator.process_request(user_request)

        # Step 3: 验证结果
        assert result["success"] == True
        assert "result" in result

        result_data = result["result"]

        # 验证工作流完整
        assert "alert_analysis" in result_data
        assert "final_report" in result_data

        # 验证报告生成
        assert "report" in result_data["final_report"]

    @pytest.mark.asyncio
    async def test_alert_to_vuln_pipeline(self, orchestrator):
        """测试Alert → Vuln的串联"""

        # 给定：AlertAnalysis发现真实威胁
        # 当：传递给VulnHuntingAgent
        # 那么：应该进行漏洞分析

        mock_alert_with_threat = {
            "true_threats": [
                {
                    "id": "threat-001",
                    "type": "exploit",
                    "cve_suspected": "CVE-2024-5678"
                }
            ]
        }

        # 直接调用VulnHuntingAgent
        vuln_result = await orchestrator._execute_vuln_analysis(
            context=None,  # 需要mock context
            alert_result=mock_alert_with_threat
        )

        assert vuln_result is not None


# tests/test_contracts.py
class TestAgentContracts:
    """契约测试 - 验证Agent间接口契约"""

    def test_alert_output_matches_vuln_input(self, mock_alert_output):
        """
        验证AlertAgent输出格式
        能够被VulnAgent正确解析
        """
        from agents.alert_analysis_agent import AlertAnalysisOutput

        # 解析Alert输出
        output = AlertAnalysisOutput(**mock_alert_output)

        # 验证关键字段存在
        assert output.result.true_threats is not None
        assert output.result.iocs is not None

        # 这些字段将被传递给VulnAgent
        assert hasattr(output.result.true_threats[0], 'id')
        assert hasattr(output.result.iocs[0], 'type')

    def test_vuln_output_matches_report_input(self, mock_vuln_output):
        """
        验证VulnAgent输出格式
        能够被ReportAgent正确解析
        """
        from agents.vuln_hunting_agent import VulnHuntingOutput

        output = VulnHuntingOutput(**mock_vuln_output)

        assert output.result.vulnerabilities is not None
        assert output.result.remediation_plans is not None
```

### 3.3 Mock服务

```python
# tests/mocks/mock_agents.py
from unittest.mock import AsyncMock, MagicMock
from typing import Dict, Any


class MockAlertAgent:
    """Mock AlertAnalysisAgent，用于测试"""

    async def execute(self, task_id: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "task_id": task_id,
            "status": "success",
            "result": {
                "total_analyzed": 5,
                "true_threats": [
                    {
                        "id": "mock-threat-001",
                        "type": "bruteforce",
                        "severity": "medium"
                    }
                ],
                "false_positives": [],
                "needs_investigation": [],
                "confidence": 0.9,
                "recommended_actions": ["review_logs"],
                "iocs": [],
                "affected_assets": []
            }
        }


class MockVulnAgent:
    """Mock VulnHuntingAgent，用于测试"""

    async def execute(self, task_id: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "task_id": task_id,
            "status": "success",
            "result": {
                "total_analyzed": 1,
                "vulnerabilities": [
                    {
                        "cve_id": "MOCK-2024-0001",
                        "severity": "low"
                    }
                ],
                "high_risk_count": 0,
                "remediation_plans": []
            }
        }


class MockReportAgent:
    """Mock ReportGeneratorAgent，用于测试"""

    async def execute(self, task_id: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "task_id": task_id,
            "status": "success",
            "result": {
                "report_id": "mock-report-001",
                "report_content": "# Mock Security Report\n\n...",
                "summary": "Mock report summary",
                "key_findings": ["Finding 1"],
                "recommendations": ["Recommendation 1"],
                "confidence": 0.8
            }
        }
```

---

## 4. 持续集成流程

### 4.1 Git工作流

```
main (保护分支)
  │
  ├── feature/alert-agent ──→ PR ──→ 单元测试 ──→ 合并
  │
  ├── feature/vuln-agent ──→ PR ──→ 单元测试 ──→ 合并
  │
  ├── feature/orchestrator ──→ PR ──→ 单元测试 ──→ 合并
  │
  └── develop ──→ 集成测试 ──→ 部署测试环境
```

### 4.2 CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, develop, 'feature/**']
  pull_request:
    branches: [main, develop]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-asyncio pytest-cov

      - name: Run contract tests
        run: |
          pytest tests/test_contracts.py -v

      - name: Run unit tests
        run: |
          pytest tests/test_*agent.py -v --cov=agents

      - name: Run integration tests
        run: |
          pytest tests/test_integration.py -v

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

### 4.3 代码质量检查

```bash
# pre-commit hook
#!/bin/bash
# .git/hooks/pre-commit

echo "Running pre-commit checks..."

# 1. 格式化代码
black --check src/

# 2. 类型检查
mypy src/

# 3. Lint检查
ruff check src/

# 4. 运行契约测试
pytest tests/test_contracts.py -v

echo "Pre-commit checks passed!"
```

---

## 5. 接口契约文档

### 5.1 Agent间契约

```
┌─────────────────┐     ┌─────────────────┐
│  AlertAgent     │ ──▶ │   VulnAgent     │
├─────────────────┤     ├─────────────────┤
│ 输出:           │     │ 输入:           │
│ - true_threats  │ ──▶ │ - vulnerabilities│
│ - iocs          │ ──▶ │ - related_iocs   │
│ - affected_assets│ ──▶ │ - related_alerts │
└─────────────────┘     └─────────────────┘

┌─────────────────┐     ┌─────────────────┐
│   VulnAgent     │ ──▶ │   ReportAgent    │
├─────────────────┤     ├─────────────────┤
│ 输出:           │     │ 输入:           │
│ - vulnerabilities│ ──▶│ - vuln_results   │
│ - remediation   │ ──▶ │ - raw_data       │
│   _plans        │     │                 │
└─────────────────┘     └─────────────────┘
```

### 5.2 数据契约示例

```python
# contracts/alert_to_vuln_contract.py
"""
AlertAgent → VulnAgent 契约

当AlertAgent.status = "success" 且存在 true_threats 时：
VulnAgent应该接收并处理
"""

AlertOutput = {
    "status": "success",
    "result": {
        "true_threats": [
            {
                "id": str,           # 必须
                "type": str,          # 必须: malware/bruteforce/exploit/...
                "severity": str,      # 必须: low/medium/high/critical
                "source_ip": str,     # 可选
                "cve_suspected": str, # 可选
                "ioc": List[str]      # 可选
            }
        ],
        "iocs": [
            {
                "type": str,  # ip/domain/hash/url
                "value": str
            }
        ]
    }
}
```

---

## 6. 团队协作指南

### 6.1 代码所有权

| 模块 | 负责人 | 职责 |
|------|--------|------|
| orchestrator/ | 架构师 | 核心编排逻辑 |
| agents/alert_* | 成员A | AlertAnalysisAgent |
| agents/vuln_* | 成员B | VulnHuntingAgent |
| agents/report_* | 成员C | ReportGeneratorAgent |
| rag/ | 成员D | RAG知识库 |
| tests/ | 全员 | 各自负责自己模块的测试 |

### 6.2 代码Review清单

```markdown
## PR Review 检查清单

### 接口检查
- [ ] 输入格式是否符合schema？
- [ ] 输出格式是否符合schema？
- [ ] 错误处理是否完整？

### 测试检查
- [ ] 是否有单元测试？
- [ ] 是否通过契约测试？
- [ ] 是否通过集成测试？

### 文档检查
- [ ] 是否更新了接口文档？
- [ ] 是否有使用示例？
```

### 6.3 集成时间表

```
Week 1-2: 各Agent独立开发
           ↓
Week 3: 接口定义冻结 + 契约测试编写
           ↓
Week 4: 集成测试 + 修复接口问题
           ↓
Week 5: 端到端测试 + 优化
```

---

## 7. 调试工具

### 7.1 链路追踪

```python
# 工具：追踪Agent执行链路
class AgentTracer:
    def __init__(self):
        self.traces = []

    def trace(self, agent_name: str, input_data: Any, output_data: Any):
        self.traces.append({
            "agent": agent_name,
            "input": input_data,
            "output": output_data,
            "timestamp": time.time()
        })

    def get_trace(self, task_id: str) -> List[Dict]:
        return [t for t in self.traces if t.get("task_id") == task_id]

    def print_trace(self, task_id: str):
        for trace in self.get_trace(task_id):
            print(f"=== {trace['agent']} ===")
            print(f"Input: {trace['input']}")
            print(f"Output: {trace['output']}")
```

### 7.2 日志规范

```python
# 统一的日志格式
LOG_FORMAT = "[{task_id}] {agent} - {action} - {result} - {duration}ms"

# 每个Agent必须记录的日志
logger.info(f"[{task_id}] {agent_name} - START - input_size={len(input_data)}")
logger.info(f"[{task_id}] {agent_name} - SUCCESS - output_size={len(output_data)}")
logger.error(f"[{task_id}] {agent_name} - FAILED - error={error_message}")
```

---

## 8. 下一步行动

### 立即执行

1. **定义接口Schema** - 所有Agent开发者开会确认
2. **创建测试骨架** - 建立tests/目录结构
3. **编写契约测试** - 验证Agent间接口
4. **设置CI/CD** - 配置GitHub Actions

### 团队分工

- **架构师**：负责orchestrator + 接口定义
- **Agent开发者**：各自负责一个Agent + 对应测试
- **集成负责人**：负责集成测试 + 修复问题

---

**您觉得这个集成方案如何？需要我帮您实现测试框架的代码吗？**