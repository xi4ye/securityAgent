from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from loguru import logger
import sys
from pathlib import Path

sys.path.insert(0, ".")

from agents import (
    SecurityReportAgent,
    AlertAnalysisAgent,
    VulnHuntingAgent,
    AlertBatchProcessor
)
from tools import FirewallTool, EDRTool, LogQueryTool
from config.settings import API_HOST, API_PORT, LOG_LEVEL
from data import DataPipeline

logger.remove()
logger.add(sys.stderr, level=LOG_LEVEL)

app = FastAPI(
    title="AI+安全大模型平台智能体",
    description="基于LangChain和DeepSeek的安全运营智能体系统",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

firewall_tool = FirewallTool()
edr_tool = EDRTool()
log_tool = LogQueryTool()

security_report_agent = SecurityReportAgent(
    name="SecurityReportAgent",
    system_prompt=""
)

alert_analysis_agent = AlertAnalysisAgent(
    name="AlertAnalysisAgent",
    system_prompt=""
)

vuln_hunting_agent = VulnHuntingAgent(
    name="VulnHuntingAgent",
    system_prompt=""
)

alert_batch_processor = AlertBatchProcessor(alert_analysis_agent)


class ChatRequest(BaseModel):
    message: str = Field(..., description="用户输入的消息")
    agent_type: str = Field(..., description="Agent类型: report, alert, vuln")


class AlertBatchRequest(BaseModel):
    alerts: List[Dict[str, Any]] = Field(..., description="告警列表")


class VulnProcessRequest(BaseModel):
    vuln_data: Dict[str, Any] = Field(..., description="漏洞数据")


class DataLoadRequest(BaseModel):
    file_path: str = Field(..., description="数据文件路径")
    limit: Optional[int] = Field(None, description="限制加载的记录数")


class LogAnalysisRequest(BaseModel):
    logs: List[Dict[str, Any]] = Field(..., description="日志列表")
    analysis_type: str = Field("full", description="分析类型: full, alert_only, stats_only")


@app.get("/")
async def root():
    return {
        "message": "AI+安全大模型平台智能体 API",
        "version": "1.0.0",
        "agents": ["SecurityReportAgent", "AlertAnalysisAgent", "VulnHuntingAgent"]
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.post("/api/chat")
async def chat(request: ChatRequest):
    try:
        logger.info(f"收到聊天请求: {request.agent_type}")

        if request.agent_type == "report":
            response = security_report_agent.chat(request.message)
        elif request.agent_type == "alert":
            response = alert_analysis_agent.chat(request.message)
        elif request.agent_type == "vuln":
            response = vuln_hunting_agent.chat(request.message)
        else:
            raise HTTPException(status_code=400, detail="未知的Agent类型")

        return {
            "success": True,
            "agent": request.agent_type,
            "response": response
        }

    except Exception as e:
        logger.error(f"聊天请求处理失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/alerts/batch")
async def process_alerts_batch(request: AlertBatchRequest):
    try:
        logger.info(f"收到批量告警处理请求: {len(request.alerts)} 条告警")

        result = alert_batch_processor.process_batch(request.alerts)

        return {
            "success": True,
            "result": result
        }

    except Exception as e:
        logger.error(f"批量告警处理失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/vuln/process")
async def process_vulnerability(request: VulnProcessRequest):
    try:
        logger.info(f"收到漏洞处理请求: {request.vuln_data.get('id', 'unknown')}")

        workflow = vuln_hunting_agent.process_vulnerability(request.vuln_data)

        return {
            "success": True,
            "workflow": workflow
        }

    except Exception as e:
        logger.error(f"漏洞处理失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/tools/firewall")
async def execute_firewall(action: str, ip_address: str, duration: int = 3600):
    try:
        result = firewall_tool.execute({
            "action": action,
            "ip_address": ip_address,
            "duration": duration
        })
        return result
    except Exception as e:
        logger.error(f"防火墙操作失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/tools/edr")
async def execute_edr(action: str, endpoint_id: str):
    try:
        result = edr_tool.execute({
            "action": action,
            "endpoint_id": endpoint_id
        })
        return result
    except Exception as e:
        logger.error(f"EDR操作失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/tools/logs")
async def query_logs(query: str, time_range: str = "1h", limit: int = 100):
    try:
        result = log_tool.execute({
            "query": query,
            "time_range": time_range,
            "limit": limit
        })
        return result
    except Exception as e:
        logger.error(f"日志查询失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/data/load")
async def load_data(request: DataLoadRequest):
    """加载NSL-KDD数据集并转换为安全日志格式"""
    try:
        logger.info(f"加载数据文件: {request.file_path}")

        if not Path(request.file_path).exists():
            raise HTTPException(status_code=404, detail=f"文件不存在: {request.file_path}")

        pipeline = DataPipeline(request.file_path)
        result = pipeline.load_and_process(limit=request.limit)

        return {
            "success": True,
            "data": {
                "total_records": result["total_records"],
                "stats": result["stats"],
                "attack_distribution": result["attack_distribution"],
                "sample_logs": result["logs"][:5] if result["logs"] else []
            }
        }

    except Exception as e:
        logger.error(f"数据加载失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/data/analyze")
async def analyze_logs(request: LogAnalysisRequest):
    """分析安全日志"""
    try:
        logger.info(f"分析 {len(request.logs)} 条日志")

        logs = request.logs

        if request.analysis_type == "stats_only":
            stats = {
                "total": len(logs),
                "attacks": sum(1 for log in logs if log.get("is_attack", False)),
                "normal": sum(1 for log in logs if not log.get("is_attack", False)),
                "severity_distribution": {},
                "attack_types": {}
            }

            for log in logs:
                severity = log.get("severity", "unknown")
                attack_type = log.get("event_type", "unknown")

                stats["severity_distribution"][severity] = \
                    stats["severity_distribution"].get(severity, 0) + 1
                stats["attack_types"][attack_type] = \
                    stats["attack_types"].get(attack_type, 0) + 1

            return {"success": True, "stats": stats}

        elif request.analysis_type == "alert_only":
            attacks = [log for log in logs if log.get("is_attack", False)]
            return {
                "success": True,
                "attacks": attacks,
                "attack_count": len(attacks)
            }

        else:
            prompt = f"""请分析以下安全日志数据，生成详细的安全分析报告。

日志总数: {len(logs)}

请提供：
1. 安全态势概述
2. 主要威胁类型分析
3. 高危事件详情
4. 建议的处置措施
5. 安全趋势分析

日志数据:
{logs[:50]}"""

            analysis = alert_analysis_agent.chat(prompt)

            return {
                "success": True,
                "analysis": analysis,
                "stats": {
                    "total": len(logs),
                    "attacks": sum(1 for log in logs if log.get("is_attack", False))
                }
            }

    except Exception as e:
        logger.error(f"日志分析失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/data/stats")
async def get_data_stats():
    """获取数据统计信息"""
    try:
        kdd_test_path = "/home/wangwei/superAgent/KDDTest.txt"

        if not Path(kdd_test_path).exists():
            return {
                "success": False,
                "error": "KDDTest.txt not found"
            }

        pipeline = DataPipeline(kdd_test_path)
        result = pipeline.load_and_process()

        return {
            "success": True,
            "stats": result["stats"],
            "attack_distribution": result["attack_distribution"]
        }

    except Exception as e:
        logger.error(f"获取统计信息失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    logger.info(f"启动API服务器: {API_HOST}:{API_PORT}")
    uvicorn.run(app, host=API_HOST, port=API_PORT)