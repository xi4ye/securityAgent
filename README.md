# AI+安全大模型平台智能体系统

基于 **LangGraph + LangChain + FastAPI + DeepSeek** 的安全运营智能体系统

## 🏗️ 架构概览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SecurityOrchestrator                                │
│                           (LangGraph中央编排器)                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐         ┌───────────────┐         ┌───────────────┐
│    Log       │         │    Alert     │         │     Vuln     │
│  Collector   │────────▶│  Analysis     │────────▶│   Hunting    │
│   Agent      │         │   Agent       │         │    Agent     │
└───────────────┘         └───────┬───────┘         └───────┬───────┘
                                  │                             │
                                  │ RAG                         │ RAG
                                  ▼                             ▼
                        ┌───────────────┐             ┌───────────────┐
                        │   Threat     │             │    CVE/      │
                        │    Intel     │             │   ATT&CK     │
                        │   Agent      │             │   知识库      │
                        └───────────────┘             └───────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│ Remediation   │       │   Security    │       │   Report     │
│   Agent       │──────▶│   Report      │◀──────│  Generator   │
│               │       │   Agent       │       │   Agent      │
└───────────────┘       └───────────────┘       └───────────────┘
```

## 📁 项目结构

```
security-agent/
├── agents/                      # Agent层（6个智能体）
│   ├── base_agent.py                   # 基础Agent抽象类
│   ├── log_collector_agent.py          # 日志采集Agent
│   ├── alert_analysis_agent.py         # 告警分析Agent
│   ├── threat_intel_agent.py           # 威胁情报Agent
│   ├── vuln_hunting_agent.py           # 漏洞分析Agent
│   ├── remediation_agent.py            # 响应处置Agent
│   └── security_report_agent.py        # 报告生成Agent
├── orchestrator/                  # 编排器层（LangGraph）
│   └── langgraph_orchestrator.py       # LangGraph编排器
├── rag/                           # RAG知识库层
│   └── knowledge_base.py               # ChromaDB知识库
├── tools/                         # 工具层
│   └── firewall_tool.py               # 防火墙、EDR、日志工具
├── api/                           # API层
│   └── main.py                          # FastAPI主程序
├── data/                          # 数据层
│   └── nsl_kdd_loader.py              # NSL-KDD数据加载器
├── config/                        # 配置
│   └── settings.py
├── docs/                          # 文档
│   ├── findings.md                    # 研究发现
│   ├── team_division.md               # 团队分工
│   └── integration_plan.md            # 集成计划
├── tests/                         # 测试
│   ├── unit/                         # 单元测试
│   ├── integration/                  # 集成测试
│   └── mocks/                        # Mock Agents
├── requirements.txt
└── .env.example
```

## 🤖 Agent职责

| Agent | 职责 | RAG支持 | 评分占比 |
|-------|------|---------|---------|
| **LogCollectorAgent** | 日志采集、标准化、分片 | ❌ | - |
| **AlertAnalysisAgent** | 告警分析、威胁判断 | ✅ ATT&CK | 基础任务 |
| **ThreatIntelAgent** | 威胁情报管理、IoC匹配 | ✅ 情报库 | 进阶任务 |
| **VulnHuntingAgent** | 漏洞深度分析、风险评估 | ✅ CVE | 基础任务 |
| **RemediationAgent** | 响应处置建议、自动执行 | ✅ 安全策略 | 进阶任务 |
| **SecurityReportAgent** | 生成分析报告 | ⚠️ 模板 | 基础任务 |

## 🛠️ 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/YOUR_USERNAME/securityAgent.git
cd securityAgent
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env 填入你的 DeepSeek API Key
```

### 4. 运行测试

```bash
pytest tests/
```

### 5. 启动服务

```bash
python -m api.main
# 或
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

### 6. 访问API文档

打开浏览器访问: http://localhost:8000/docs

## 📡 API接口

### 执行安全分析

```bash
POST /api/analyze
{
  "task": "分析过去24小时的安全告警",
  "source": "nsl_kdd",
  "limit": 1000
}
```

### 查看工作流状态

```bash
GET /api/status
```

## 📚 技术栈

- **Agent框架**: LangGraph + LangChain
- **编排器**: LangGraph StateGraph
- **大模型**: DeepSeek API
- **向量数据库**: ChromaDB
- **Web框架**: FastAPI
- **日志**: Loguru
- **测试**: Pytest

## 👥 团队分工

详见 [docs/team_division.md](docs/team_division.md)

## 📅 开发时间线

| 阶段 | 时间 | 任务 |
|------|------|------|
| Phase 1 | Week 1-2 | 架构设计 + Agent骨架 |
| Phase 2 | Week 3-6 | 并行开发 |
| Phase 3 | Week 7-8 | 集成测试 |
| Phase 4 | Week 9-10 | 文档演示 |

## ⚠️ 注意事项

- 所有Agent都定义在 `agents/` 目录
- 使用LangGraph进行Agent编排
- RAG知识库需要额外数据（ATT&CK、CVE等）
- 日志数据来源：NSL-KDD数据集

## 📝 TODO

- [ ] 完成所有6个Agent的实现
- [ ] 构建ATT&CK RAG知识库
- [ ] 构建CVE RAG知识库
- [ ] 完善集成测试
- [ ] 制作演示PPT
