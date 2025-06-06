"""阿里云资产和数据流收集主模块"""
import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# 导入已实现的子收集器
from .compute import ComputeAssetCollector
from .network import NetworkAssetCollector
from .storage import StorageAssetCollector
# 以下收集器尚未实现，将在后续开发中添加
from .database import DatabaseAssetCollector
from .domain_router import DomainRouterAssetCollector
from .transit_gateway import TransitGatewayAssetCollector
from .iam import IAMAssetCollector
from .security import SecurityAssetCollector
from .monitoring import MonitoringAssetCollector

class AliyunAssetCollector:
    """阿里云资产和数据流收集主类"""

    def __init__(self, session):
        """
        初始化阿里云资产收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        
        # 初始化已实现的收集器
        self.compute_collector = ComputeAssetCollector(session)
        self.network_collector = NetworkAssetCollector(session)
        self.storage_collector = StorageAssetCollector(session)
        
        # 数据库收集器
        self.database_collector = DatabaseAssetCollector(session)
        
        # 域名与路由收集器
        self.domain_router_collector = DomainRouterAssetCollector(session)
        
        # 传输网关及高级网络收集器
        self.transit_gateway_collector = TransitGatewayAssetCollector(session)
        
        # IAM资源收集器
        self.iam_collector = IAMAssetCollector(session)
        
        # 安全资源收集器
        self.security_collector = SecurityAssetCollector(session)
        
        # 监控资源收集器
        self.monitoring_collector = MonitoringAssetCollector(session)
        
        
        # 以下收集器尚未实现，将在后续开发中添加
        # self.flow_paths_generator = DataFlowPathsGenerator(session)
        
    def collect_all_assets(self) -> Dict[str, Any]:
        """
        收集所有阿里云资产

        Returns:
            Dict[str, Any]: 所有阿里云资产
        """
        logger.info("开始收集所有阿里云资产...")
        
        # 使用已实现的收集器收集资产
        assets = {
            'compute': self.compute_collector.get_all_compute_assets(),
            'network': self.network_collector.get_all_network_assets(),
            'storage': self.storage_collector.get_all_storage_assets(),
            'database': self.database_collector.get_all_database_assets(),
            'domain_router': self.domain_router_collector.get_all_domain_router_assets(),
            'transit_gateway': self.transit_gateway_collector.get_all_transit_gateway_assets(),
            'iam': self.iam_collector.get_all_iam_assets(),
            'security': self.security_collector.get_all_security_assets(),
            'monitoring': self.monitoring_collector.get_all_monitoring_assets(),
        }
        
        logger.info("所有阿里云资产收集完成")
        return assets

    
    def collect_assets_and_generate_flows(self, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        收集所有资产并生成数据流路径

        Args:
            output_dir: 输出目录

        Returns:
            Dict[str, Any]: 包含资产和数据流路径的字典
        """
        assets = self.collect_all_assets()
        
        return {
            'type': 'aliyun',
            'assets': assets,
        }


def collect_aliyun_assets_and_flows(session, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    收集阿里云资产和数据流的便捷函数

    Args:
        session: 阿里云会话对象
        output_dir: 输出目录

    Returns:
        Dict[str, Any]: 包含资产和数据流的字典
    """
    collector = AliyunAssetCollector(session)
    return collector.collect_assets_and_generate_flows(output_dir)