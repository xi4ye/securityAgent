# 团队分工计划

**项目**: AI+安全大模型平台智能体系统
**团队规模**: 5人
**日期**: 2026-05-11

---

## 总体分工

| 成员 | 核心模块 | 职责 | RAG知识库 |
|------|---------|------|----------|
| **成员A** | Orchestrator架构师 | LangGraph架构、Agent调度、接口定义 | - |
| **成员B** | AlertAnalysisAgent | 告警分析、威胁判断 | ATT&CK框架 |
| **成员C** | VulnHuntingAgent | 漏洞深度分析、风险评估 | CVE漏洞库 |
| **成员D** | RemediationAgent + LogCollector | 响应处置、日志采集 | 安全策略 |
| **成员E** | ReportAgent + API | 报告生成、接口开发 | 报告模板 |

---

## 分工详解

### 成员A：Orchestrator架构师 ⭐最核心

**职责**：
1. 设计LangGraph工作流架构
2. 定义Agent间接口契约（Schema）
3. 实现状态管理和调度逻辑
4. 编写单元测试和集成测试

**交付物**：
- `orchestrator/core.py` - LangGraph主程序
- `orchestrator/state.py` - 状态定义
- `tests/test_orchestrator.py`

**关键里程碑**：必须先完成接口定义，其他成员才能并行开发

---

### 成员B：AlertAnalysisAgent + ThreatIntel

**职责**：
1. 实现AlertAnalysisAgent
2. 实现ThreatIntelAgent
3. 收集和格式化ATT&CK数据
4. 构建ATT&CK RAG知识库

**交付物**：
- `agents/alert_analysis_agent.py`
- `agents/threat_intel_agent.py`
- `rag/attck_knowledge_base.py`
- `data/attck_data.json`

**RAG数据来源**：
- https://attack.mitre.org/（官方Enterprise ATT&CK）

---

### 成员C：VulnHuntingAgent + CVE RAG

**职责**：
1. 实现VulnHuntingAgent
2. 收集和格式化CVE数据
3. 构建CVE RAG知识库

**交付物**：
- `agents/vuln_hunting_agent.py`
- `rag/cve_knowledge_base.py`
- `data/cve_data.json`

**RAG数据来源**：
- https://cve.mitre.org/
- https://nvd.nist.gov/

---

### 成员D：RemediationAgent + LogCollector

**职责**：
1. 实现RemediationAgent（建议模式）
2. 实现LogCollectorAgent
3. NSL-KDD数据加载模块
4. 构建安全策略RAG知识库

**交付物**：
- `agents/remediation_agent.py`
- `agents/log_collector_agent.py`
- `data/nsl_kdd_loader.py`
- `rag/security_policy_kb.py`

**RAG数据来源**：
- 等保2.0、GDPR等安全合规文档
- 企业安全策略最佳实践

---

### 成员E：ReportAgent + API集成

**职责**：
1. 实现SecurityReportAgent
2. 完善FastAPI接口
3. 编写API文档
4. 准备演示PPT

**交付物**：
- `agents/report_generator_agent.py`
- `api/main.py`
- `docs/api_docs.md`
- `docs/presentation.pptx`

---

## 阶段性分工（动态调整）

### 阶段1：架构设计（第1-2周）

| 成员 | 任务重点 |
|------|---------|
| **成员A** | 核心：设计LangGraph架构，定义接口契约 |
| **成员B** | 收集ATT&CK数据 |
| **成员C** | 收集CVE数据 |
| **成员D** | 预处理NSL-KDD数据 |
| **成员E** | 设计报告模板，准备API框架 |

**关键里程碑**：成员A完成接口定义

---

### 阶段2：并行开发（第3-6周）

| 成员 | 任务重点 |
|------|---------|
| **成员A** | 集成各Agent到Orchestrator |
| **成员B** | 开发AlertAgent，测试RAG效果 |
| **成员C** | 开发VulnAgent，测试RAG效果 |
| **成员D** | 开发RemediationAgent + LogCollector |
| **成员E** | 开发ReportAgent，完善API |

**关键里程碑**：各Agent独立测试通过

---

### 阶段3：集成测试（第7-8周）

| 成员 | 任务重点 |
|------|---------|
| **全员** | 集成联调，修复问题 |
| **成员A** | 优化Orchestrator逻辑 |
| **成员E** | 完善API文档 |

**关键里程碑**：端到端测试通过

---

### 阶段4：文档演示（第9-10周）

| 成员 | 任务重点 |
|------|---------|
| **成员B** | 完善ATT&CK RAG |
| **成员C** | 完善CVE RAG |
| **成员D** | 完善安全策略RAG |
| **成员E** | 制作PPT和演示视频 |
| **全员** | 准备答辩 |

---

## 数据准备工作分配

| 数据类型 | 负责人 | 来源 | 状态 |
|---------|--------|------|------|
| NSL-KDD日志 | 成员D | 已下载，待处理 | ⚠️ 待处理 |
| ATT&CK框架 | 成员B | attack.mitre.org | ⚠️ 待下载 |
| CVE漏洞库 | 成员C | cve.mitre.org | ⚠️ 待下载 |
| 安全策略 | 成员D | 公开文档 | ⚠️ 待收集 |

---

## 依赖关系

```
成员A完成接口定义
        ↓
成员B/C/D/E并行开发各自Agent
        ↓
全员集成测试
        ↓
全员文档演示
```

**注意**：成员A的工作是其他所有人的前置条件！

---

## 风险与调整

### 可能需要调整的情况

1. **成员A能力不足**
   - 调整：全员先学LangGraph基础，成员A专注核心设计

2. **RAG数据获取困难**
   - 调整：先使用模拟数据，后续替换真实数据

3. **Agent集成复杂度高**
   - 调整：增加阶段2时间，或减少Agent数量

4. **成员变动**
   - 调整：重新评估分工，确保核心模块有backup

---

## 沟通机制建议

| 频率 | 形式 | 内容 |
|------|------|------|
| 每日 | 线上 | 进度同步（30分钟） |
| 每周 | 线下 | 问题讨论+下周计划 |
| 里程碑 | 评审 | 代码Review+演示 |
