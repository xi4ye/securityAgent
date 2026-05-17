from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from enum import Enum
import time


class MessageType(str, Enum):
    USER_COMMAND = "user_command"
    AGENT_REQUEST = "agent_request"
    AGENT_RESPONSE = "agent_response"
    TOOL_REQUEST = "tool_request"
    TOOL_RESPONSE = "tool_response"
    ORCHESTRATOR_COMMAND = "orchestrator_command"
    FINAL_REPORT = "final_report"


class TaskContext(BaseModel):
    task_id: str
    original_request: str
    parsed_intent: str = ""
    task_type: str = "general_query"
    status: str = "pending"

    execution_history: List[Dict[str, Any]] = []
    agent_results: Dict[str, Any] = {}

    shared_context: Dict[str, Any] = {
        "alerts": [],
        "vulnerabilities": [],
        "ioc": [],
        "affected_assets": [],
        "timeline": []
    }

    current_phase: str = "init"
    next_actions: List[str] = []

    thought_history: List[str] = []
    action_history: List[str] = []
    observation_history: List[str] = []

    class Config:
        use_enum_values = True


class SharedDataStore:
    def __init__(self):
        self._store: Dict[str, Any] = {}

    def set(self, key: str, value: Any):
        self._store[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self._store.get(key, default)

    def append(self, key: str, value: Any):
        if key not in self._store:
            self._store[key] = []
        if isinstance(self._store[key], list):
            self._store[key].append(value)

    def get_all(self) -> Dict[str, Any]:
        return self._store.copy()

    def clear(self):
        self._store.clear()