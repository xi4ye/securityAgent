from typing import List, Dict, Any
from .base_agent import BaseAgent


class AlertAnalysisAgent(BaseAgent):
    def get_system_prompt(self) -> str:
        return """你是一个专业的安全告警分析专家，负责判断告警是否为真实威胁。

你的职责：
1. 分析告警的上下文和特征
2. 关联历史告警和已知攻击模式
3. 评估告警的可信度和严重性
4. 区分真实威胁和误报

分析维度：
- 告警特征（类型、来源、目标）
- 攻击指标（IoC）
- 上下文关联（时间、地点、用户行为）
- 历史模式（是否重复、已知模式）

输出格式：
- 判断结果：真实威胁 / 误报 / 需要进一步调查
- 置信度：0-100%
- 分析理由：简要说明判断依据
- 建议操作：忽略/标记/升级/立即处置

注意：
- 宁可误报，不可漏报
- 复杂情况标注"需要进一步调查"
- 提供具体的下一步行动建议"""


class AlertAnalysisAgentWithRAG(AlertAnalysisAgent):
    def __init__(self, retriever, **kwargs):
        super().__init__(**kwargs)
        self.retriever = retriever

    def get_system_prompt(self) -> str:
        base_prompt = super().get_system_prompt()
        return base_prompt + """

你可以使用ATT&CK知识库来关联告警与已知攻击技术。
使用RAG检索来获取：
- 相关的攻击手法和防御建议
- 类似的误报案例
- 最新的威胁情报"""


class AlertBatchProcessor:
    def __init__(self, alert_agent: AlertAnalysisAgent):
        self.alert_agent = alert_agent

    def process_batch(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = []
        true_threats = []
        false_positives = []
        needs_investigation = []

        for alert in alerts:
            result = self.alert_agent.chat(
                f"分析告警：{alert.get('description', alert.get('name', 'Unknown'))}\n"
                f"告警详情：{alert}"
            )

            alert_result = {
                "alert_id": alert.get("id", "unknown"),
                "analysis": result
            }
            results.append(alert_result)

            if "真实威胁" in result or "高风险" in result:
                true_threats.append(alert_result)
            elif "误报" in result or "低风险" in result:
                false_positives.append(alert_result)
            else:
                needs_investigation.append(alert_result)

        return {
            "total": len(alerts),
            "true_threats": true_threats,
            "false_positives": false_positives,
            "needs_investigation": needs_investigation,
            "summary": {
                "true_threats_count": len(true_threats),
                "false_positives_count": len(false_positives),
                "needs_investigation_count": len(needs_investigation)
            }
        }