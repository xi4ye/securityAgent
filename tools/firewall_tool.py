from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
import httpx
from loguru import logger

from config.settings import FIREWALL_API_URL, EDR_API_URL, LOG_API_URL


class BaseTool(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        pass

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description
        }


class FirewallTool(BaseTool):
    def __init__(self, api_url: str = FIREWALL_API_URL):
        super().__init__(
            name="firewall_control",
            description="控制防火墙规则，包括封禁和解封IP地址"
        )
        self.api_url = api_url

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        action = params.get("action", "block")
        ip_address = params.get("ip_address")
        duration = params.get("duration", 3600)
        reason = params.get("reason", "安全威胁")

        if not ip_address:
            return {"success": False, "error": "缺少IP地址"}

        try:
            logger.info(f"执行防火墙操作: {action} - {ip_address}")

            return {
                "success": True,
                "action": action,
                "ip_address": ip_address,
                "duration": duration,
                "reason": reason,
                "status": "pending_confirmation"
            }

        except Exception as e:
            logger.error(f"防火墙操作失败: {e}")
            return {"success": False, "error": str(e)}

    def block_ip(self, ip_address: str, duration: int = 3600, reason: str = "安全威胁") -> Dict[str, Any]:
        return self.execute({
            "action": "block",
            "ip_address": ip_address,
            "duration": duration,
            "reason": reason
        })

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        return self.execute({
            "action": "unblock",
            "ip_address": ip_address
        })


class EDRTool(BaseTool):
    def __init__(self, api_url: str = EDR_API_URL):
        super().__init__(
            name="edr_control",
            description="控制终端检测与响应(EDR)系统，包括隔离终端、收集取证数据"
        )
        self.api_url = api_url

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        action = params.get("action", "isolate")
        endpoint_id = params.get("endpoint_id")
        reason = params.get("reason", "安全威胁")

        if not endpoint_id:
            return {"success": False, "error": "缺少终端ID"}

        try:
            logger.info(f"执行EDR操作: {action} - {endpoint_id}")

            return {
                "success": True,
                "action": action,
                "endpoint_id": endpoint_id,
                "reason": reason,
                "status": "pending_confirmation"
            }

        except Exception as e:
            logger.error(f"EDR操作失败: {e}")
            return {"success": False, "error": str(e)}

    def isolate_endpoint(self, endpoint_id: str, reason: str = "安全威胁") -> Dict[str, Any]:
        return self.execute({
            "action": "isolate",
            "endpoint_id": endpoint_id,
            "reason": reason
        })

    def collect_forensics(self, endpoint_id: str) -> Dict[str, Any]:
        return self.execute({
            "action": "collect_forensics",
            "endpoint_id": endpoint_id
        })


class LogQueryTool(BaseTool):
    def __init__(self, api_url: str = LOG_API_URL):
        super().__init__(
            name="log_query",
            description="查询安全日志和事件数据"
        )
        self.api_url = api_url

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        query = params.get("query", "*")
        time_range = params.get("time_range", "1h")
        limit = params.get("limit", 100)

        try:
            logger.info(f"执行日志查询: {query}")

            return {
                "success": True,
                "query": query,
                "time_range": time_range,
                "results": [],
                "count": 0
            }

        except Exception as e:
            logger.error(f"日志查询失败: {e}")
            return {"success": False, "error": str(e)}

    def search_events(self, keyword: str, time_range: str = "24h") -> Dict[str, Any]:
        return self.execute({
            "query": keyword,
            "time_range": time_range
        })