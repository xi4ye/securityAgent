# 研究发现 - AI+安全大模型平台智能体系统

**项目**: AI+安全大模型平台的智能体研究
**竟赛**: 挑战杯揭榜挂帅
**日期**: 2026-05-11

---

## 比赛题目分析

### 题目来源
- 发榜单位: 深信服科技股份有限公司、张家口默然教育科技有限公司
- 题目编号: XH-202614

### 核心要求
1. **基础任务 (70分)**: 场景化安全智能体构建
   - 安全报告自动生成
   - 告警误报剔除
   - 漏洞排查与闭环

2. **进阶任务 (20分)**: 领域知识增强与工具扩展
   - RAG检索增强
   - 安全知识库构建
   - ATT&CK技战术图谱

3. **挑战任务 (10分)**: 超级智能体与自主闭环
   - CoT思维链推理
   - 跨域协同
   - 零人工干预

### 技术要求
- 平台: 深信服AI安全平台
- 模型: DeepSeek、Qwen、安全GPT
- 框架: LangChain等开源框架

---

## 技术选型决策

### 已选定方案

| 组件 | 选型 | 原因 |
|------|------|------|
| **Agent框架** | LangGraph | 支持多Agent协作、循环执行、状态管理，原生适合复杂工作流 |
| **RAG组件** | LangChain RAG | 成熟稳定，与LangGraph无缝集成 |
| Web框架 | FastAPI | 高性能，自动文档，易于部署 |
| 向量数据库 | ChromaDB | 轻量级，易于集成，API友好 |
| LLM | DeepSeek V4 Flash | 成本低，性能强，支持API调用 |
| 编程语言 | Python | 团队熟悉，AI生态完善 |
| **数据来源** | NSL-KDD | 已下载的真实入侵检测数据集（22,543条记录） |

### 备选方案（未选择）

| 方案 | 原因 |
|------|------|
| 纯LangChain | 无法优雅处理多Agent循环协作 |
| Dify/LangGPT | 可视化虽好，但不够灵活 |
| CrewAI/AutoGPT | 学习曲线陡，不适合新手团队 |
| Milvus/Pinecone | 需要额外配置，增加复杂度 |

---

## 项目架构设计（LangGraph + 6个Agent）

### 整体架构

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
        │
        │ RAG
        ▼
┌───────────────┐
│    安全策略   │
│   知识库     │
└───────────────┘
```

### Agent职责说明

| Agent | 职责 | 输入 | 输出 | RAG支持 |
|-------|------|------|------|--------|
| **LogCollectorAgent** | 日志采集、标准化 | NSL-KDD数据 | 标准日志 | ❌ |
| **AlertAnalysisAgent** | 告警分析、威胁判断 | 日志 | 威胁列表 | ✅ ATT&CK |
| **VulnHuntingAgent** | 漏洞深度分析 | 威胁 | 漏洞报告 | ✅ CVE |
| **ThreatIntelAgent** | 威胁情报管理 | 外部情报 | 情报数据 | ✅ 情报库 |
| **RemediationAgent** | 响应处置建议 | 漏洞报告 | 处置指令 | ✅ 安全策略 |
| **SecurityReportAgent** | 生成分析报告 | 所有结果 | 安全报告 | ⚠️ 模板 |

### 数据流

```
LogCollector ──▶ AlertAnalysis ──▶ VulnHunting ──▶ Remediation
     │                 │                 │               │
     │                 │ RAG             │ RAG           │ RAG
     │                 ▼                 ▼               ▼
     │          ┌──────────┐      ┌──────────┐    ┌──────────┐
     │          │ThreatIntel│     │CVE/ATT&CK│    │安全策略  │
     │          └──────────┘      └──────────┘    └──────────┘
     │                                                        │
     └────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                           SecurityReport
                                    │
                                    ▼
                               最终报告
```

### LangGraph优势

| 特性 | LangGraph | 纯LangChain |
|------|-----------|------------|
| 多Agent协作 | ✅ 原生支持 | ❌ 需要自己实现 |
| 循环执行（ReAct） | ✅ 内置 | ❌ 需要自己实现 |
| 状态管理 | ✅ 自动传递 | ❌ 手动管理 |
| 可视化调试 | ✅ 图形化 | ⚠️ 复杂 |

### 外部数据依赖

| 数据类型 | 来源 | 用途 | 状态 |
|---------|------|------|------|
| 安全日志 | NSL-KDD | Agent分析样本 | ✅ 已下载 |
| CVE漏洞库 | cve.mitre.org | VulnAgent RAG | ⚠️ 待下载 |
| ATT&CK框架 | attack.mitre.org | AlertAgent RAG | ⚠️ 待下载 |
| 安全政策 | 公开文档 | RemediationAgent RAG | ⚠️ 待收集 |

---

## 已完成工作

### 项目骨架创建

已创建完整的三层架构项目：

```
security-agent/
├── agents/              # Agent层
│   ├── base_agent.py           # 基础Agent类
│   ├── security_report_agent.py # 安全报告Agent
│   ├── alert_analysis_agent.py  # 告警分析Agent
│   └── vuln_hunting_agent.py    # 漏洞挖掘Agent
├── rag/                # RAG知识库层
│   └── knowledge_base.py        # ChromaDB知识库
├── tools/              # 工具层
│   └── firewall_tool.py         # 防火墙、EDR、日志工具
├── api/                # API层
│   └── main.py                 # FastAPI主程序
├── config/             # 配置
│   └── settings.py
└── requirements.txt     # 依赖
```

---

## 待解决问题

### 1. 深信服平台API
- 状态: 未获取
- 影响: 无法完全模拟真实环境
- 应对: 先用Mock实现，后续对接

### 2. 知识库内容
- 状态: 待收集
- 影响: RAG效果依赖数据质量
- 应对: 收集公开的安全文档和政策

### 3. 评估指标
- 状态: 待确定
- 影响: 无法量化Agent效果
- 应对: 制定内部评估标准

---

## 参考资源

### 官方文档
- LangChain: https://python.langchain.com/
- FastAPI: https://fastapi.tiangolo.com/
- ChromaDB: https://docs.trychroma.com/

### 安全知识库
- ATT&CK: https://attack.mitre.org/
- CVE数据库: https://cve.mitre.org/
- NVD: https://nvd.nist.gov/

### 比赛信息
- 官网: www.tiaozhanbei.net
- 报名时间: 2026年5月30日-6月30日
- 作品提交截止: 2026年9月15日