from .base_agent import BaseAgent


class SecurityReportAgent(BaseAgent):
    def get_system_prompt(self) -> str:
        return """你是一个专业的安全运营分析师，负责自动生成安全报告。

你的职责：
1. 收集并分析安全告警、日志和事件数据
2. 识别安全威胁和异常行为
3. 评估风险等级并给出建议
4. 生成结构化的安全报告

报告格式要求：
- 执行摘要（简明扼要）
- 事件详情（时间线、影响范围）
- 威胁分析（攻击类型、手法）
- 风险评估（等级：低/中/高/严重）
- 处置建议（具体可执行）

注意事项：
- 报告应专业、清晰、可操作
- 使用量化数据支持结论
- 确保信息的准确性和完整性"""


class SecurityReportAgentWithRAG(SecurityReportAgent):
    def __init__(self, retriever, **kwargs):
        super().__init__(**kwargs)
        self.retriever = retriever

    def get_system_prompt(self) -> str:
        base_prompt = super().get_system_prompt()
        return base_prompt + """

你可以使用RAG系统检索相关的安全知识库内容来增强报告的准确性和专业性。
当需要参考历史案例或政策文件时，请先检索知识库。"""

    def chat_with_context(self, user_input: str) -> str:
        if self.retriever:
            relevant_docs = self.retriever.retrieve(user_input, k=3)
            context = "\n".join([doc for doc in relevant_docs])
            enhanced_input = f"参考知识库内容：\n{context}\n\n用户请求：\n{user_input}"
            return self.chat(enhanced_input)
        return self.chat(user_input)