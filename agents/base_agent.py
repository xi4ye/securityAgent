from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_community.chat_models import ChatDeepSeek
from loguru import logger

from config.settings import DEEPSEEK_API_KEY, DEEPSEEK_MODEL, DEEPSEEK_API_BASE


class BaseAgent(ABC):
    def __init__(
        self,
        name: str,
        system_prompt: str,
        model_name: str = DEEPSEEK_MODEL,
        api_key: str = DEEPSEEK_API_KEY,
        api_base: str = DEEPSEEK_API_BASE,
        temperature: float = 0.7,
        tools: Optional[List[Any]] = None
    ):
        self.name = name
        self.system_prompt = system_prompt
        self.tools = tools or []

        self.llm = ChatDeepSeek(
            model=model_name,
            api_key=api_key,
            base_url=api_base,
            temperature=temperature,
            streaming=False
        )

        self.conversation_history: List[Dict[str, str]] = []

    @abstractmethod
    def get_system_prompt(self) -> str:
        pass

    def build_prompt(self, user_input: str) -> List:
        messages = [SystemMessage(content=self.get_system_prompt())]
        for msg in self.conversation_history:
            if msg["role"] == "user":
                messages.append(HumanMessage(content=msg["content"]))
            elif msg["role"] == "assistant":
                messages.append(AIMessage(content=msg["content"]))

        messages.append(HumanMessage(content=user_input))
        return messages

    def chat(self, user_input: str) -> str:
        try:
            messages = self.build_prompt(user_input)
            response = self.llm.invoke(messages)
            answer = response.content

            self.conversation_history.append({"role": "user", "content": user_input})
            self.conversation_history.append({"role": "assistant", "content": answer})

            logger.info(f"[{self.name}] Response generated successfully")
            return answer

        except Exception as e:
            logger.error(f"[{self.name}] Error during chat: {e}")
            return f"抱歉，处理您的请求时出现错误: {str(e)}"

    def clear_history(self):
        self.conversation_history = []

    def get_name(self) -> str:
        return self.name