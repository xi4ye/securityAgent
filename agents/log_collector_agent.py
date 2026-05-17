from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent
from loguru import logger


class LogCollectorAgent(BaseAgent):
    """
    日志采集Agent

    职责：
    - 从外部数据源采集安全日志
    - 标准化日志格式
    - 日志分片处理

    TODO:
    - [ ] 实现NSL-KDD数据加载
    - [ ] 实现实时日志采集（可选）
    - [ ] 实现日志分片逻辑
    """

    def __init__(self, **kwargs):
        system_prompt = """你是一个日志采集专家。

你的职责：
1. 从各种来源采集安全日志
2. 将日志标准化为统一格式
3. 处理大量日志的分片

输入：原始日志数据或数据源配置
输出：标准化后的日志列表

请确保：
- 每条日志都有唯一ID
- 时间戳格式统一
- 字段命名规范"""
        super().__init__(name="LogCollectorAgent", system_prompt=system_prompt, **kwargs)

    def get_system_prompt(self) -> str:
        return self.system_prompt

    async def collect_logs(self, source: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        从指定来源采集日志

        Args:
            source: 数据来源标识（如 'nsl_kdd', 'firewall', 'ids'）
            limit: 限制采集数量

        Returns:
            标准化日志列表
        """
        logger.info(f"[{self.name}] Collecting logs from {source}")

        # TODO: 实现具体的数据采集逻辑
        # 示例：
        # if source == 'nsl_kdd':
        #     return self._collect_from_nsl_kdd(limit)

        return []

    async def standardize_logs(self, raw_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        标准化日志格式

        Args:
            raw_logs: 原始日志列表

        Returns:
            标准化后的日志列表
        """
        logger.info(f"[{self.name}] Standardizing {len(raw_logs)} logs")

        standardized = []
        for idx, log in enumerate(raw_logs):
            standardized_log = {
                "log_id": f"LOG-{idx:06d}",
                "timestamp": log.get("timestamp"),
                "source": log.get("source", "unknown"),
                "event_type": log.get("event_type", "unknown"),
                "severity": log.get("severity", "low"),
                "description": log.get("description", ""),
                "raw_data": log
            }
            standardized.append(standardized_log)

        return standardized

    async def chunk_logs(self, logs: List[Dict[str, Any]], chunk_size: int = 100) -> List[List[Dict[str, Any]]]:
        """
        日志分片

        Args:
            logs: 日志列表
            chunk_size: 每片大小

        Returns:
            分片后的日志列表
        """
        logger.info(f"[{self.name}] Chunking {len(logs)} logs into size {chunk_size}")

        chunks = []
        for i in range(0, len(logs), chunk_size):
            chunks.append(logs[i:i + chunk_size])

        logger.info(f"[{self.name}] Created {len(chunks)} chunks")
        return chunks
