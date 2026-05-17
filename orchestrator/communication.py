from typing import Dict, Any, List, Optional
from .context import TaskContext, MessageType, AgentMessage
import uuid
import time
from loguru import logger


class AgentCommunicationProtocol:
    def __init__(self, context: TaskContext):
        self.context = context
        self.message_queue: List[AgentMessage] = []

    def _generate_msg_id(self) -> str:
        return str(uuid.uuid4())

    async def send_message(
        self,
        receiver: str,
        msg_type: MessageType,
        content: Dict[str, Any]
    ) -> AgentMessage:
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
        messages = []
        for agent_name in ["AlertAnalysisAgent", "VulnHuntingAgent", "ReportGeneratorAgent"]:
            msg = await self.send_message(agent_name, msg_type, content)
            messages.append(msg)
        return messages