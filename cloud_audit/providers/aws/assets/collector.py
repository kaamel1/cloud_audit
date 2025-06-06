"""
AWS资产收集和数据流生成的主模块
"""
import logging
import os
from typing import Dict, Any, Optional

from .compute import ComputeAssetCollector
from .network import NetworkAssetCollector
from .storage import StorageAssetCollector
from .database import DatabaseAssetCollector
from .domain_router import DomainRouterAssetCollector
from .transit_gateway import TransitGatewayAssetCollector
from .iam import IAMAssetCollector
from .cloudfront import CloudFrontAssetCollector
from .waf import WAFAssetCollector
from .acm_global import ACMGlobalAssetCollector
from .organizations import OrganizationsAssetCollector

logger = logging.getLogger(__name__)

class AWSAssetCollector:
    """AWS资产和数据流收集主类"""

    def __init__(self, session):
        """
        初始化AWS资产收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        # 区域性服务collector
        self.compute_collector = ComputeAssetCollector(session)
        self.network_collector = NetworkAssetCollector(session)
        self.storage_collector = StorageAssetCollector(session)
        self.database_collector = DatabaseAssetCollector(session)
        self.domain_router_collector = DomainRouterAssetCollector(session)
        self.transit_gateway_collector = TransitGatewayAssetCollector(session)
        self.iam_collector = IAMAssetCollector(session)
        
        # 全局服务collector
        self.cloudfront_collector = CloudFrontAssetCollector(session)
        self.waf_collector = WAFAssetCollector(session)
        self.acm_global_collector = ACMGlobalAssetCollector(session)
        self.organizations_collector = OrganizationsAssetCollector(session)
        

    def collect_all_assets(self) -> Dict[str, Any]:
        """
        收集所有AWS区域性资产

        Returns:
            Dict[str, Any]: 所有AWS区域性资产
        """
        logger.info("开始收集所有AWS区域性资产...")
        
        assets = {
            'compute': self.compute_collector.get_all_compute_assets(),
            'network': self.network_collector.get_all_network_assets(),
            'storage': self.storage_collector.get_all_storage_assets(),
            'database': self.database_collector.get_all_database_assets(),
            'domain_router': self.domain_router_collector.get_all_domain_router_assets(),
            'transit_gateway': self.transit_gateway_collector.get_all_transit_gateway_assets(),
            'iam': self.iam_collector.get_all_iam_assets(),
        }
        
        logger.info("所有AWS区域性资产收集完成")
        return assets
    
    def collect_all_assets_global(self) -> Dict[str, Any]:
        """
        收集所有AWS全局资产（不区分区域的服务）

        Returns:
            Dict[str, Any]: 所有AWS全局资产
        """
        logger.info("开始收集所有AWS全局资产...")
        
        global_assets = {}
        
        # CloudFront distributions (全局CDN服务)
        try:
            global_assets['cloudfront'] = self.cloudfront_collector.get_all_cloudfront_assets()
            logger.info("CloudFront资产收集完成")
        except Exception as e:
            logger.warning(f"收集CloudFront资产失败: {str(e)}")
            global_assets['cloudfront'] = {}
        
        # AWS WAF (全局Web应用防火墙)
        try:
            global_assets['waf'] = self.waf_collector.get_all_waf_assets()
            logger.info("WAF资产收集完成")
        except Exception as e:
            logger.warning(f"收集WAF资产失败: {str(e)}")
            global_assets['waf'] = {}
        
        # AWS Certificate Manager全局证书（用于CloudFront）
        try:
            global_assets['acm_global'] = self.acm_global_collector.get_all_acm_global_assets()
            logger.info("ACM Global资产收集完成")
        except Exception as e:
            logger.warning(f"收集ACM全局证书资产失败: {str(e)}")
            global_assets['acm_global'] = {}
        
        # AWS Organizations（组织管理服务）
        try:
            global_assets['organizations'] = self.organizations_collector.get_all_organizations_assets()
            logger.info("Organizations资产收集完成")
        except Exception as e:
            logger.warning(f"收集Organizations资产失败: {str(e)}")
            global_assets['organizations'] = {}
        
        # IAM也是全局服务，但为了兼容性也放在这里
        try:
            global_assets['iam'] = self.iam_collector.get_all_iam_assets()
            logger.info("IAM资产收集完成")
        except Exception as e:
            logger.warning(f"收集IAM资产失败: {str(e)}")
            global_assets['iam'] = {}
        
        # Route53也是全局服务
        try:
            global_assets['domain_router'] = self.domain_router_collector.get_all_domain_router_assets()
            logger.info("Route53资产收集完成")
        except Exception as e:
            logger.warning(f"收集Route53资产失败: {str(e)}")
            global_assets['domain_router'] = {}
        
        logger.info("所有AWS全局资产收集完成")
        return global_assets
    
    def collect_all_assets_complete(self) -> Dict[str, Any]:
        """
        收集所有AWS资产（包括区域性和全局资产）

        Returns:
            Dict[str, Any]: 包含区域性和全局资产的完整字典
        """
        logger.info("开始收集所有AWS资产（区域性+全局）...")
        
        # 收集区域性资产
        regional_assets = self.collect_all_assets()
        
        # 收集全局资产
        global_assets = self.collect_all_assets_global()
        
        complete_assets = {
            'regional': regional_assets,
            'global': global_assets
        }
        
        logger.info("所有AWS资产收集完成（区域性+全局）")
        return complete_assets
 
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
            'type': 'aws',
            'assets': assets,
        }


def collect_aws_assets_and_flows(session, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    收集AWS资产和生成数据流路径的便捷函数

    Args:
        session: AWS会话对象
        output_dir: 输出目录

    Returns:
        Dict[str, Any]: 包含资产和数据流路径的字典
    """
    collector = AWSAssetCollector(session)
    return collector.collect_assets_and_generate_flows(output_dir)


def collect_aws_assets_global(session) -> Dict[str, Any]:
    """
    收集AWS全局资产的便捷函数

    Args:
        session: AWS会话对象

    Returns:
        Dict[str, Any]: 所有AWS全局资产
    """
    collector = AWSAssetCollector(session)
    return collector.collect_all_assets_global()


def collect_aws_assets_complete(session) -> Dict[str, Any]:
    """
    收集所有AWS资产（区域性+全局）的便捷函数

    Args:
        session: AWS会话对象

    Returns:
        Dict[str, Any]: 包含区域性和全局资产的完整字典
    """
    collector = AWSAssetCollector(session)
    return collector.collect_all_assets_complete() 