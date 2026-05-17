import json
import uuid
from typing import List, Dict, Any, Optional
from pathlib import Path
import random
import csv

class Logger:
    @staticmethod
    def info(msg):
        print(f"[INFO] {msg}")
    @staticmethod
    def error(msg):
        print(f"[ERROR] {msg}")

logger = Logger()


NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack", "difficulty_level"
]

ATTACK_SEVERITY = {
    "normal": "low",
    "neptune": "critical",
    "back": "high",
    "land": "critical",
    "pod": "high",
    "smurf": "critical",
    "teardrop": "high",
    "ipsweep": "medium",
    "nmap": "medium",
    "portsweep": "medium",
    "satan": "medium",
    "mscan": "medium",
    "saint": "medium",
    "ftp_write": "high",
    "guess_passwd": "high",
    "imap": "high",
    "multihop": "high",
    "phf": "critical",
    "spy": "critical",
    "warezclient": "high",
    "warezmaster": "critical",
    "buffer_overflow": "critical",
    "loadmodule": "critical",
    "perl": "critical",
    "rootkit": "critical",
}

ATTACK_CATEGORIES = {
    "normal": "Normal Traffic",
    "neptune": "DoS Attack",
    "back": "DoS Attack",
    "land": "DoS Attack",
    "pod": "DoS Attack",
    "smurf": "DoS Attack",
    "teardrop": "DoS Attack",
    "ipsweep": "Probe Attack",
    "nmap": "Probe Attack",
    "portsweep": "Probe Attack",
    "satan": "Probe Attack",
    "mscan": "Probe Attack",
    "saint": "Probe Attack",
    "ftp_write": "R2L Attack",
    "guess_passwd": "R2L Attack",
    "imap": "R2L Attack",
    "multihop": "R2L Attack",
    "phf": "R2L Attack",
    "spy": "R2L Attack",
    "warezclient": "R2L Attack",
    "warezmaster": "R2L Attack",
    "buffer_overflow": "U2R Attack",
    "loadmodule": "U2R Attack",
    "perl": "U2R Attack",
    "rootkit": "U2R Attack",
}


class NSLKDDCsvLoader:
    """NSL-KDD数据集CSV加载器（纯Python实现）"""

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.data: List[Dict[str, Any]] = []

    def load(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """加载CSV文件"""
        logger.info(f"Loading NSL-KDD data from {self.file_path}")

        self.data = []

        with open(self.file_path, 'r') as f:
            reader = csv.reader(f)
            for idx, row in enumerate(reader):
                if limit and idx >= limit:
                    break

                if len(row) >= 43:
                    row_dict = dict(zip(NSL_KDD_COLUMNS, row[:43]))
                    self.data.append(row_dict)

        logger.info(f"Loaded {len(self.data)} records")
        return self.data

    def to_security_logs(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """转换为安全日志格式"""
        if not self.data:
            self.load()

        data = self.data[:limit] if limit else self.data

        logs = []
        for idx, row in enumerate(data):
            log = self._convert_row_to_log(row, idx)
            logs.append(log)

        return logs

    def _convert_row_to_log(self, row: Dict[str, str], idx: int) -> Dict[str, Any]:
        """将CSV行转换为安全日志格式"""
        attack_type = row.get("attack", "unknown")
        severity = ATTACK_SEVERITY.get(attack_type, "medium")
        category = ATTACK_CATEGORIES.get(attack_type, "Unknown Attack")

        try:
            src_bytes = int(row.get("src_bytes", 0))
            dst_bytes = int(row.get("dst_bytes", 0))
            duration = int(row.get("duration", 0))
        except ValueError:
            src_bytes = dst_bytes = duration = 0

        return {
            "log_id": f"LOG-KDD-{idx:06d}",
            "timestamp": None,
            "source": "nsl_kdd_ids",
            "source_type": "network_intrusion_detection",
            "event_type": attack_type,
            "category": category,
            "severity": severity,
            "description": self._generate_description(row, attack_type, category),
            "src_ip": self._generate_fake_ip(),
            "src_port": random.randint(1024, 65535),
            "dst_ip": self._generate_fake_ip(),
            "dst_port": self._map_service_to_port(row.get("service", "http")),
            "protocol": row.get("protocol_type", "tcp"),
            "duration_seconds": duration,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "logged_in": row.get("logged_in", "0") == "1",
            "is_guest_login": row.get("is_guest_login", "0") == "1",
            "count": int(row.get("count", 0)) if row.get("count", "0").isdigit() else 0,
            "srv_count": int(row.get("srv_count", 0)) if row.get("srv_count", "0").isdigit() else 0,
            "serror_rate": float(row.get("serror_rate", 0)),
            "dst_host_count": int(row.get("dst_host_count", 0)) if row.get("dst_host_count", "0").isdigit() else 0,
            "dst_host_srv_count": int(row.get("dst_host_srv_count", 0)) if row.get("dst_host_srv_count", "0").isdigit() else 0,
            "raw_features": {
                "service": row.get("service", ""),
                "flag": row.get("flag", ""),
                "num_failed_logins": row.get("num_failed_logins", "0"),
                "num_compromised": row.get("num_compromised", "0"),
                "root_shell": row.get("root_shell", "0"),
                "su_attempted": row.get("su_attempted", "0"),
            },
            "label": attack_type,
            "difficulty_level": row.get("difficulty_level", "0"),
            "is_attack": attack_type != "normal"
        }

    def _generate_description(self, row: Dict[str, str], attack_type: str, category: str) -> str:
        """生成日志描述"""
        if attack_type == "normal":
            return f"Normal network traffic: {row.get('service', 'unknown')} connection"

        return f"{category}: {attack_type} attack detected. Service: {row.get('service', 'unknown')}, " \
               f"Duration: {row.get('duration', '0')}s, Src bytes: {row.get('src_bytes', '0')}, " \
               f"Dst bytes: {row.get('dst_bytes', '0')}"

    def _generate_fake_ip(self) -> str:
        """生成假IP（用于演示）"""
        return f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"

    def _map_service_to_port(self, service: str) -> int:
        """将服务类型映射到端口号"""
        service_port_map = {
            "http": 80,
            "ftp": 21,
            "smtp": 25,
            "telnet": 23,
            "ssh": 22,
            "dns": 53,
            "pop3": 110,
            "imap": 143,
            "snmp": 161,
            "https": 443,
        }
        return service_port_map.get(service, 80)


class SecurityLogChunker:
    """安全日志分片处理器"""

    def __init__(self, chunk_size: int = 100):
        self.chunk_size = chunk_size

    def chunk_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """将日志列表分片"""
        chunks = []
        total_logs = len(logs)

        for i in range(0, total_logs, self.chunk_size):
            chunk_logs = logs[i:i + self.chunk_size]
            chunk = {
                "chunk_id": i // self.chunk_size,
                "total_chunks": (total_logs + self.chunk_size - 1) // self.chunk_size,
                "start_index": i,
                "end_index": min(i + self.chunk_size, total_logs),
                "log_count": len(chunk_logs),
                "logs": chunk_logs,
                "stats": self._calculate_chunk_stats(chunk_logs)
            }
            chunks.append(chunk)

        return chunks

    def _calculate_chunk_stats(self, chunk_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """计算分片统计信息"""
        attack_count = sum(1 for log in chunk_logs if log.get("is_attack", False))
        normal_count = len(chunk_logs) - attack_count

        severity_counts = {}
        category_counts = {}

        for log in chunk_logs:
            severity = log.get("severity", "unknown")
            category = log.get("category", "Unknown")

            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1

        return {
            "total": len(chunk_logs),
            "attacks": attack_count,
            "normal": normal_count,
            "attack_ratio": round(attack_count / len(chunk_logs), 3) if chunk_logs else 0,
            "severity_distribution": severity_counts,
            "category_distribution": category_counts
        }


class DataPipeline:
    """数据处理流水线"""

    def __init__(self, data_path: str):
        self.data_path = data_path
        self.loader = None
        self.chunker = SecurityLogChunker(chunk_size=100)

    def load_and_process(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """加载并处理数据"""
        logger.info(f"Starting data pipeline for {self.data_path}")

        self.loader = NSLKDDCsvLoader(self.data_path)
        self.loader.load(limit=limit)

        logs = self.loader.to_security_logs()

        chunks = self.chunker.chunk_logs(logs)

        stats = self._generate_overall_stats(logs)

        return {
            "total_records": len(logs),
            "logs": logs,
            "chunks": chunks,
            "stats": stats,
            "attack_distribution": self._get_attack_distribution(logs)
        }

    def _generate_overall_stats(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成总体统计"""
        attack_logs = [log for log in logs if log.get("is_attack", False)]
        normal_logs = [log for log in logs if not log.get("is_attack", False)]

        severity_counts = {}
        for log in logs:
            severity = log.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total": len(logs),
            "attacks": len(attack_logs),
            "normal": len(normal_logs),
            "attack_ratio": round(len(attack_logs) / len(logs), 3) if logs else 0,
            "severity_distribution": severity_counts
        }

    def _get_attack_distribution(self, logs: List[Dict[str, Any]]) -> Dict[str, int]:
        """获取攻击类型分布"""
        attack_types = {}
        for log in logs:
            if log.get("is_attack", False):
                attack_type = log.get("event_type", "unknown")
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        return attack_types
