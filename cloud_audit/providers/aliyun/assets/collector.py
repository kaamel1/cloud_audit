"""阿里云区域资产和数据流收集主模块"""
import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# 导入区域相关的子收集器
from .compute import ComputeAssetCollector
from .network import NetworkAssetCollector
from .storage import StorageAssetCollector
from .database import DatabaseAssetCollector
from .domain_router import DomainRouterAssetCollector
from .transit_gateway import TransitGatewayAssetCollector
from .iam import IAMAssetCollector  # 注意：IAM在区域收集器中返回空结果
from .security import SecurityAssetCollector
from .monitoring import MonitoringAssetCollector

class AliyunAssetCollector:
    """阿里云区域资产和数据流收集主类"""

    def __init__(self, session):
        """
        初始化阿里云区域资产收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        
        # 初始化区域相关的收集器
        self.compute_collector = ComputeAssetCollector(session)
        self.network_collector = NetworkAssetCollector(session)
        self.storage_collector = StorageAssetCollector(session)
        self.database_collector = DatabaseAssetCollector(session)
        self.domain_router_collector = DomainRouterAssetCollector(session)  # 主要收集DNS解析线路等区域相关配置
        self.transit_gateway_collector = TransitGatewayAssetCollector(session)  # 主要收集高速通道、VPN网关等区域资源
        self.iam_collector = IAMAssetCollector(session)  # IAM在区域收集器中返回空结果
        self.security_collector = SecurityAssetCollector(session)
        self.monitoring_collector = MonitoringAssetCollector(session)  # 当前返回空结构，监控资源都是全局的
        
        
        # 以下收集器尚未实现，将在后续开发中添加
        # self.flow_paths_generator = DataFlowPathsGenerator(session)
        
    def collect_all_assets(self) -> Dict[str, Any]:
        """
        收集所有阿里云区域相关资产
        
        注意：全局资产（如IAM用户、域名注册、云企业网、监控告警规则等）请使用 AliyunGlobalAssetCollector

        Returns:
            Dict[str, Any]: 所有阿里云区域相关资产
        """
        logger.info(f"开始收集阿里云区域 {self.session.region_id} 的相关资产...")
        
        # 使用区域收集器收集资产
        assets = {
            'compute': self.compute_collector.get_all_compute_assets(),
            'network': self.network_collector.get_all_network_assets(),
            'storage': self.storage_collector.get_all_storage_assets(),
            'database': self.database_collector.get_all_database_assets(),
            'domain_router': self.domain_router_collector.get_all_domain_router_assets(),  # 主要是DNS解析线路配置
            'transit_gateway': self.transit_gateway_collector.get_all_transit_gateway_assets(),  # 主要是高速通道、VPN网关
            'iam': self.iam_collector.get_all_iam_assets(),  # 返回空结果
            'security': self.security_collector.get_all_security_assets(),
            'monitoring': self.monitoring_collector.get_all_monitoring_assets(),  # 返回空结构，监控资源都是全局的
        }
        
        logger.info(f"阿里云区域 {self.session.region_id} 的相关资产收集完成")
        logger.info("全局资产（IAM、域名注册、云企业网、监控告警规则等）请使用 AliyunGlobalAssetCollector 获取")
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
            'type': 'aliyun_regional',
            'region': self.session.region_id,
            'assets': assets,
        }


def collect_aliyun_assets_and_flows(session, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    收集阿里云区域资产和数据流的便捷函数

    Args:
        session: 阿里云会话对象
        output_dir: 输出目录

    Returns:
        Dict[str, Any]: 包含区域资产和数据流的字典
    """
    collector = AliyunAssetCollector(session)
    return collector.collect_assets_and_generate_flows(output_dir)