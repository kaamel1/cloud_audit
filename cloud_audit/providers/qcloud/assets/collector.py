"""
腾讯云区域资产和数据流收集主模块
"""
import logging
import os
from typing import Dict, Any, Optional

from .compute import ComputeAssetCollector
from .network import NetworkAssetCollector
from .database import DatabaseAssetCollector
from .security import SecurityAssetCollector
from .monitor import MonitorAssetCollector

logger = logging.getLogger(__name__)

class QCloudAssetCollector:
    """腾讯云区域资产和数据流收集主类"""

    def __init__(self, session):
        """
        初始化腾讯云区域资产收集器

        Args:
            session: 腾讯云会话对象
        """
        self.session = session
        # 区域性服务collector
        self.compute_collector = ComputeAssetCollector(session)
        self.network_collector = NetworkAssetCollector(session)
        self.database_collector = DatabaseAssetCollector(session)
        self.security_collector = SecurityAssetCollector(session)
        self.monitor_collector = MonitorAssetCollector(session)

    def collect_all_assets(self) -> Dict[str, Any]:
        """
        收集所有腾讯云区域性资产
        
        注意：全局资产（如CAM、COS、CDN等）请使用 QCloudGlobalAssetCollector

        Returns:
            Dict[str, Any]: 所有腾讯云区域性资产
        """
        logger.info("开始收集所有腾讯云区域性资产...")
        
        assets = {
            'compute': self.compute_collector.get_all_compute_assets(),
            'network': self.network_collector.get_all_network_assets(),
            'database': self.database_collector.get_all_database_assets(),
            'security': self.security_collector.get_all_security_assets(),
            'monitor': self.monitor_collector.get_all_monitor_assets(),
        }
        
        logger.info("所有腾讯云区域性资产收集完成")
        logger.info("全局资产（CAM、COS、CDN等）请使用 QCloudGlobalAssetCollector 获取")
        return assets
 
    def collect_assets_and_generate_flows(self, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        收集所有区域资产并生成数据流路径

        Args:
            output_dir: 输出目录

        Returns:
            Dict[str, Any]: 包含区域资产和数据流路径的字典
        """
        assets = self.collect_all_assets()
        
        return {
            'type': 'qcloud_regional',
            'region': self.session.region,
            'assets': assets,
        }


def collect_qcloud_assets_and_flows(session, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    收集腾讯云区域资产和生成数据流路径的便捷函数

    Args:
        session: 腾讯云会话对象
        output_dir: 输出目录

    Returns:
        Dict[str, Any]: 包含区域资产和数据流路径的字典
    """
    collector = QCloudAssetCollector(session)
    return collector.collect_assets_and_generate_flows(output_dir) 