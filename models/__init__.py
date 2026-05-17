"""
统一数据模型定义

包含所有Agent使用的数据结构定义
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class Severity(str, Enum):
    """严重程度枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(str, Enum):
    """动作类型枚举"""
    BLOCK_IP = "block_ip"
    ISOLATE = "isolate"
    QUARANTINE = "quarantine"
    NOTIFY = "notify"
    SCAN = "scan"


class Priority(str, Enum):
    """优先级枚举"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SecurityLog(BaseModel):
    """标准化安全日志"""
    log_id: str = Field(..., description="日志唯一ID")
    timestamp: str = Field(..., description="时间戳 (ISO格式)")
    source: str = Field(..., description="来源类型")
    source_type: Optional[str] = Field(None, description="设备类型")
    event_type: str = Field(..., description="事件类型")
    severity: str = Field(..., description="严重程度: low/medium/high/critical")
    description: str = Field(..., description="描述")
    src_ip: Optional[str] = Field(None, description="源IP")
    dst_ip: Optional[str] = Field(None, description="目标IP")
    src_port: Optional[int] = Field(None, description="源端口")
    dst_port: Optional[int] = Field(None, description="目标端口")
    protocol: Optional[str] = Field(None, description="协议")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="原始数据")


class AlertResult(BaseModel):
    """告警分析结果"""
    log_id: str = Field(..., description="关联的日志ID")
    is_threat: bool = Field(..., description="是否为真实威胁")
    threat_type: Optional[str] = Field(None, description="威胁类型")
    severity: str = Field(..., description="严重程度")
    confidence: float = Field(..., ge=0.0, le=1.0, description="置信度 (0.0-1.0)")
    reason: str = Field(..., description="判断理由")
    recommended_actions: List[str] = Field(default_factory=list, description="建议行动")
    ttp: Optional[str] = Field(None, description="ATT&CK战术技术")


class ThreatIntel(BaseModel):
    """威胁情报"""
    is_known_threat: bool = Field(..., description="是否为已知威胁")
    threat_actors: List[str] = Field(default_factory=list, description="威胁组织")
    attack_campaigns: List[str] = Field(default_factory=list, description="攻击活动")
    confidence: float = Field(..., ge=0.0, le=1.0, description="置信度")
    source: Optional[str] = Field(None, description="情报来源")
    last_updated: Optional[str] = Field(None, description="更新时间")


class EnrichedEvent(BaseModel):
    """增强后的事件"""
    original_alert: AlertResult = Field(..., description="原始告警")
    threat_intel: ThreatIntel = Field(..., description="威胁情报")
    enriched_timestamp: str = Field(..., description="增强时间")


class VulnResult(BaseModel):
    """漏洞分析结果"""
    vuln_id: str = Field(..., description="漏洞ID")
    event_id: str = Field(..., description="关联事件ID")
    vuln_type: str = Field(..., description="漏洞类型")
    severity: str = Field(..., description="严重程度")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS评分")
    cve_id: Optional[str] = Field(None, description="CVE编号")
    affected_asset: str = Field(..., description="受影响资产")
    description: str = Field(..., description="描述")
    impact: str = Field(..., description="影响分析")
    remediation: str = Field(..., description="修复建议")
    confidence: float = Field(..., ge=0.0, le=1.0, description="置信度")


class Action(BaseModel):
    """处置动作"""
    action: str = Field(..., description="动作类型: block_ip/isolate/quarantine/notify")
    target: str = Field(..., description="目标")
    reason: str = Field(..., description="原因")
    priority: str = Field(..., description="优先级: high/medium/low")
    estimated_impact: str = Field(..., description="影响评估")


class ActionResult(BaseModel):
    """动作执行结果"""
    status: str = Field(..., description="状态: success/error/simulated")
    action: str = Field(..., description="动作类型")
    target: str = Field(..., description="目标")
    result: str = Field(..., description="执行结果")
    success: bool = Field(..., description="是否成功")
    timestamp: str = Field(..., description="执行时间")


class RemediationResult(BaseModel):
    """处置结果"""
    remediation_id: str = Field(..., description="处置ID")
    vuln_id: str = Field(..., description="关联漏洞ID")
    recommended_actions: List[Action] = Field(default_factory=list, description="建议行动列表")
    prevention_measures: List[str] = Field(default_factory=list, description="预防措施")
    confidence: float = Field(..., ge=0.0, le=1.0, description="置信度")


class AnalysisReport(BaseModel):
    """分析报告"""
    report_id: str = Field(..., description="报告ID")
    title: str = Field(..., description="标题")
    summary: str = Field(..., description="摘要")
    logs_count: int = Field(..., description="处理的日志数")
    alerts_count: int = Field(..., description="告警数")
    threats_count: int = Field(..., description="威胁数")
    vulnerabilities_count: int = Field(..., description="漏洞数")
    remediations_count: int = Field(..., description="处置数")
    content: str = Field(..., description="报告内容 (Markdown)")
    created_at: str = Field(..., description="创建时间")
    execution_time: float = Field(..., description="执行时间(秒)")


class AgentResult(BaseModel):
    """通用Agent结果"""
    status: str = Field(..., description="状态: success/error")
    agent_name: str = Field(..., description="Agent名称")
    data: Optional[Any] = Field(None, description="返回数据")
    error: Optional[str] = Field(None, description="错误信息")
    execution_time: float = Field(..., description="执行时间(秒)")
