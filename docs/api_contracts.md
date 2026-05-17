# Agent接口定义文档

**项目**: AI+安全大模型平台智能体系统
**版本**: 1.0
**日期**: 2026-05-11

---

## 1. 全局状态定义 (SecurityState)

所有Agent之间通过 `SecurityState` 传递数据：

```python
class SecurityState(TypedDict):
    # 输入参数
    task: str                           # 任务描述
    source: str                         # 数据来源 (nsl_kdd/firewall/ids)
    limit: Optional[int]               # 处理数量限制

    # 中间结果（各Agent输出）
    logs: List[Dict[str, Any]]         # 标准化日志列表
    alerts: List[Dict[str, Any]]       # 告警列表
    threats: List[Dict[str, Any]]      # 威胁列表
    vulnerabilities: List[Dict[str, Any]] # 漏洞列表
    remediations: List[Dict[str, Any]]  # 处置建议列表
    report: Optional[str]              # 最终报告

    # 状态标记
    current_agent: str                  # 当前执行中的Agent
    iteration: int                     # 当前迭代次数
    max_iterations: int                # 最大迭代次数

    # 错误信息
    error: Optional[str]               # 错误信息
```

---

## 2. Agent接口契约

### 2.1 LogCollectorAgent

```python
async def collect_logs(
    source: str,
    limit: Optional[int] = None
) -> List[SecurityLog]
```

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| source | str | ✅ | 数据来源：nsl_kdd / firewall / ids |
| limit | int | ❌ | 限制数量，默认None |

**返回**: `List[SecurityLog]`

```python
class SecurityLog(BaseModel):
    log_id: str                        # 日志唯一ID
    timestamp: str                      # 时间戳 (ISO格式)
    source: str                        # 来源类型
    source_type: str                   # 设备类型
    event_type: str                   # 事件类型
    severity: str                      # 严重程度: low/medium/high/critical
    description: str                   # 描述
    src_ip: Optional[str] = None       # 源IP
    dst_ip: Optional[str] = None       # 目标IP
    protocol: Optional[str] = None     # 协议
    raw_data: Dict[str, Any] = {}     # 原始数据
```

---

### 2.2 AlertAnalysisAgent

```python
async def analyze_alert(log: SecurityLog) -> AlertResult
```

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| log | SecurityLog | ✅ | 标准化的安全日志 |

**返回**: `AlertResult`

```python
class AlertResult(BaseModel):
    log_id: str                        # 关联的日志ID
    is_threat: bool                    # 是否为真实威胁
    threat_type: Optional[str] = None  # 威胁类型
    severity: str                      # 严重程度
    confidence: float                  # 置信度 (0.0-1.0)
    reason: str                        # 判断理由
    recommended_actions: List[str] = [] # 建议行动
```

---

### 2.3 ThreatIntelAgent

```python
async def enrich_event(event: AlertResult) -> EnrichedEvent
async def check_ioc(indicator: str, indicator_type: str) -> IOCResult
```

**enrich_event 参数**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| event | AlertResult | ✅ | 告警结果 |

**返回**: `EnrichedEvent`

```python
class EnrichedEvent(BaseModel):
    original_event: AlertResult        # 原始事件
    threat_intel: ThreatIntel          # 威胁情报
    is_known_threat: bool              # 是否为已知威胁
    threat_actors: List[str] = []      # 威胁组织
    attack_campaigns: List[str] = []   # 攻击活动
    confidence: float                  # 置信度
```

---

### 2.4 VulnHuntingAgent

```python
async def analyze_vulnerability(event: EnrichedEvent) -> VulnResult
```

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| event | EnrichedEvent | ✅ | 增强后的事件 |

**返回**: `VulnResult`

```python
class VulnResult(BaseModel):
    vuln_id: str                       # 漏洞ID
    event_id: str                       # 关联事件ID
    vuln_type: str                      # 漏洞类型
    severity: str                       # 严重程度
    cvss_score: Optional[float] = None  # CVSS评分
    cve_id: Optional[str] = None        # CVE编号
    affected_asset: str                  # 受影响资产
    description: str                     # 描述
    impact: str                         # 影响分析
    remediation: str                     # 修复建议
    confidence: float                   # 置信度
```

---

### 2.5 RemediationAgent

```python
async def generate_remediation(vuln: VulnResult) -> RemediationResult
async def execute_action(action: Action, mode: str = "simulate") -> ActionResult
```

**generate_remediation 参数**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| vuln | VulnResult | ✅ | 漏洞分析结果 |

**返回**: `RemediationResult`

```python
class RemediationResult(BaseModel):
    remediation_id: str                 # 处置ID
    vuln_id: str                        # 关联漏洞ID
    recommended_actions: List[Action]   # 建议行动列表
    prevention_measures: List[str]      # 预防措施
    confidence: float                   # 置信度
```

**Action 结构**:

```python
class Action(BaseModel):
    action: str                         # 动作类型: block_ip/isolate/quarantine/notify
    target: str                         # 目标
    reason: str                         # 原因
    priority: str                       # 优先级: high/medium/low
    estimated_impact: str                # 影响评估
```

**execute_action mode 参数**:
- `simulate`: 模拟执行（比赛用）
- `execute`: 真实执行（生产用）

---

### 2.6 SecurityReportAgent

```python
async def generate_report(
    logs: List[SecurityLog],
    alerts: List[AlertResult],
    vulnerabilities: List[VulnResult],
    remediations: List[RemediationResult]
) -> str
```

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| logs | List[SecurityLog] | ✅ | 日志列表 |
| alerts | List[AlertResult] | ✅ | 告警列表 |
| vulnerabilities | List[VulnResult] | ✅ | 漏洞列表 |
| remediations | List[RemediationResult] | ✅ | 处置列表 |

**返回**: `str` (Markdown格式报告)

---

## 3. API接口定义

### 3.1 FastAPI端点

```python
# POST /api/analyze
class AnalyzeRequest(BaseModel):
    task: str                           # 任务描述
    source: str = "nsl_kdd"           # 数据来源
    limit: Optional[int] = None        # 限制数量

class AnalyzeResponse(BaseModel):
    task: str                           # 任务描述
    logs_count: int                     # 处理日志数
    alerts_count: int                   # 告警数
    threats_count: int                  # 威胁数
    vulnerabilities_count: int          # 漏洞数
    report: str                         # 报告内容
    execution_time: float              # 执行时间(秒)
    status: str                        # 状态: success/error
```

```python
# GET /api/status
class StatusResponse(BaseModel):
    orchestrator_status: str           # 编排器状态
    agents_ready: List[str]            # 就绪的Agent列表
    rag_knowledge_bases: List[str]     # 已加载的知识库
```

```python
# POST /api/logs/load
class LoadLogsRequest(BaseModel):
    source: str                        # 数据来源
    limit: Optional[int] = None        # 限制数量

class LoadLogsResponse(BaseModel):
    logs: List[SecurityLog]           # 日志列表
    total_count: int                  # 总数
```

---

## 4. 数据流定义

```
LogCollectorAgent.collect_logs()
    ↓
[SecurityLog] → AlertAnalysisAgent.analyze_alert()
    ↓
[AlertResult] → ThreatIntelAgent.enrich_event()
    ↓
[EnrichedEvent] → VulnHuntingAgent.analyze_vulnerability()
    ↓
[VulnResult] → RemediationAgent.generate_remediation()
    ↓
[RemediationResult] → SecurityReportAgent.generate_report()
    ↓
Markdown Report
```

---

## 5. 错误处理

每个Agent返回结果时，必须处理异常：

```python
try:
    result = await agent.method(params)
    return {"status": "success", "data": result, "error": None}
except Exception as e:
    logger.error(f"Agent error: {e}")
    return {"status": "error", "data": None, "error": str(e)}
```

---

## 6. 版本历史

| 版本 | 日期 | 修改内容 |
|------|------|---------|
| 1.0 | 2026-05-11 | 初始版本 |

---

## 7. 维护者

- 成员A (Orchestrator架构师)
