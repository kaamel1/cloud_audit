"""阿里云全局资产收集主模块"""
import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# 导入全局资源收集器
from .iam_global import IAMGlobalAssetCollector
from .domain_router_global import DomainRouterGlobalAssetCollector
from .transit_gateway_global import TransitGatewayGlobalAssetCollector
from .monitoring_global import MonitoringGlobalAssetCollector
from .storage_global import StorageGlobalAssetCollector

class AliyunGlobalAssetCollector:
    """阿里云全局资产收集主类"""

    def __init__(self, session):
        """
        初始化阿里云全局资产收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        
        # 初始化全局资源收集器
        self.iam_global_collector = IAMGlobalAssetCollector(session)
        self.domain_router_global_collector = DomainRouterGlobalAssetCollector(session)
        self.transit_gateway_global_collector = TransitGatewayGlobalAssetCollector(session)
        self.monitoring_global_collector = MonitoringGlobalAssetCollector(session)
        self.storage_global_collector = StorageGlobalAssetCollector(session)
        
    def collect_all_global_assets(self) -> Dict[str, Any]:
        """
        收集所有阿里云全局资产

        Returns:
            Dict[str, Any]: 所有阿里云全局资产
        """
        logger.info("开始收集所有阿里云全局资产...")
        
        # 使用全局收集器收集资产
        global_assets = {
            'iam': self.iam_global_collector.get_all_iam_global_assets(),
            'domain_router': self.domain_router_global_collector.get_all_domain_router_global_assets(),
            'transit_gateway': self.transit_gateway_global_collector.get_all_transit_gateway_global_assets(),
            'monitoring': self.monitoring_global_collector.get_all_monitoring_global_assets(),
            'storage': self.storage_global_collector.get_all_storage_global_assets(),
        }
        
        logger.info("所有阿里云全局资产收集完成")
        return global_assets

    def collect_global_assets_and_generate_flows(self, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        收集所有全局资产并生成数据流路径

        Args:
            output_dir: 输出目录

        Returns:
            Dict[str, Any]: 包含全局资产和数据流路径的字典
        """
        global_assets = self.collect_all_global_assets()
        
        return {
            'type': 'aliyun_global',
            'assets': global_assets,
        }


def collect_aliyun_global_assets_and_flows(session, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    收集阿里云全局资产和数据流的便捷函数

    Args:
        session: 阿里云会话对象
        output_dir: 输出目录

    Returns:
        Dict[str, Any]: 包含全局资产和数据流的字典
    """
    collector = AliyunGlobalAssetCollector(session)
    return collector.collect_global_assets_and_generate_flows(output_dir) 