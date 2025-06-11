"""
AWS区域资产和数据流收集主模块
"""
import logging
import os
from typing import Dict, Any, Optional

from .compute import ComputeAssetCollector
from .network import NetworkAssetCollector
from .storage import StorageAssetCollector
from .database import DatabaseAssetCollector
from .transit_gateway import TransitGatewayAssetCollector

logger = logging.getLogger(__name__)

class AWSAssetCollector:
    """AWS区域资产和数据流收集主类"""

    def __init__(self, session):
        """
        初始化AWS区域资产收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        # 区域性服务collector
        self.compute_collector = ComputeAssetCollector(session)
        self.network_collector = NetworkAssetCollector(session)
        self.storage_collector = StorageAssetCollector(session)
        self.database_collector = DatabaseAssetCollector(session)
        self.transit_gateway_collector = TransitGatewayAssetCollector(session)

    def collect_all_assets(self) -> Dict[str, Any]:
        """
        收集所有AWS区域性资产
        
        注意：全局资产（如IAM、Route53、CloudFront、WAF、Organizations等）请使用 AWSGlobalAssetCollector

        Returns:
            Dict[str, Any]: 所有AWS区域性资产
        """
        logger.info("开始收集所有AWS区域性资产...")
        
        assets = {
            'compute': self.compute_collector.get_all_compute_assets(),
            'network': self.network_collector.get_all_network_assets(),
            'storage': self.storage_collector.get_all_storage_assets(),
            'database': self.database_collector.get_all_database_assets(),
            'transit_gateway': self.transit_gateway_collector.get_all_transit_gateway_assets(),
        }
        
        logger.info("所有AWS区域性资产收集完成")
        logger.info("全局资产（IAM、Route53、CloudFront、WAF、Organizations等）请使用 AWSGlobalAssetCollector 获取")
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
            'type': 'aws_regional',
            'region': self.session.boto3_session.region_name,
            'assets': assets,
        }


def collect_aws_assets_and_flows(session, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    收集AWS区域资产和生成数据流路径的便捷函数

    Args:
        session: AWS会话对象
        output_dir: 输出目录

    Returns:
        Dict[str, Any]: 包含区域资产和数据流路径的字典
    """
    collector = AWSAssetCollector(session)
    return collector.collect_assets_and_generate_flows(output_dir) 