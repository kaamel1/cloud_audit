"""
AWS全局资产收集主模块
"""
import logging
import os
from typing import Dict, Any, Optional

from .cloudfront_global import CloudFrontGlobalAssetCollector
from .waf_global import WAFGlobalAssetCollector
from .acm_global import ACMGlobalAssetCollector
from .organizations_global import OrganizationsGlobalAssetCollector
from .iam_global import IAMGlobalAssetCollector
from .domain_router_global import DomainRouterGlobalAssetCollector

logger = logging.getLogger(__name__)

class AWSGlobalAssetCollector:
    """AWS全局资产收集主类"""

    def __init__(self, session):
        """
        初始化AWS全局资产收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        
        # 初始化全局服务collector
        self.cloudfront_global_collector = CloudFrontGlobalAssetCollector(session)
        self.waf_global_collector = WAFGlobalAssetCollector(session)
        self.acm_global_collector = ACMGlobalAssetCollector(session)
        self.organizations_global_collector = OrganizationsGlobalAssetCollector(session)
        self.iam_global_collector = IAMGlobalAssetCollector(session)
        self.domain_router_global_collector = DomainRouterGlobalAssetCollector(session)
   
    def collect_all_global_assets(self) -> Dict[str, Any]:
        """
        收集所有AWS全局资产

        Returns:
            Dict[str, Any]: 所有AWS全局资产
        """
        logger.info("开始收集所有AWS全局资产...")
        
        global_assets = {}
        
        # CloudFront distributions (全局CDN服务)
        try:
            global_assets['cloudfront'] = self.cloudfront_global_collector.get_all_cloudfront_global_assets()
            logger.info("CloudFront全局资产收集完成")
        except Exception as e:
            logger.warning(f"收集CloudFront全局资产失败: {str(e)}")
            global_assets['cloudfront'] = {}
        
        # AWS WAF (全局Web应用防火墙)
        try:
            global_assets['waf'] = self.waf_global_collector.get_all_waf_global_assets()
            logger.info("WAF全局资产收集完成")
        except Exception as e:
            logger.warning(f"收集WAF全局资产失败: {str(e)}")
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
            global_assets['organizations'] = self.organizations_global_collector.get_all_organizations_global_assets()
            logger.info("Organizations全局资产收集完成")
        except Exception as e:
            logger.warning(f"收集Organizations全局资产失败: {str(e)}")
            global_assets['organizations'] = {}
        
        # IAM全局服务
        try:
            global_assets['iam'] = self.iam_global_collector.get_all_iam_global_assets()
            logger.info("IAM全局资产收集完成")
        except Exception as e:
            logger.warning(f"收集IAM全局资产失败: {str(e)}")
            global_assets['iam'] = {}
        
        # Route53全局服务
        try:
            global_assets['domain_router'] = self.domain_router_global_collector.get_all_domain_router_global_assets()
            logger.info("Route53全局资产收集完成")
        except Exception as e:
            logger.warning(f"收集Route53全局资产失败: {str(e)}")
            global_assets['domain_router'] = {}
        
        logger.info("所有AWS全局资产收集完成")
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
            'type': 'aws_global',
            'assets': global_assets,
        }


def collect_aws_global_assets_and_flows(session, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    收集AWS全局资产和数据流的便捷函数

    Args:
        session: AWS会话对象
        output_dir: 输出目录

    Returns:
        Dict[str, Any]: 包含全局资产和数据流的字典
    """
    collector = AWSGlobalAssetCollector(session)
    return collector.collect_global_assets_and_generate_flows(output_dir)


def collect_aws_global_assets(session) -> Dict[str, Any]:
    """
    收集AWS全局资产的便捷函数

    Args:
        session: AWS会话对象

    Returns:
        Dict[str, Any]: 所有AWS全局资产
    """
    collector = AWSGlobalAssetCollector(session)
    return collector.collect_all_global_assets()

