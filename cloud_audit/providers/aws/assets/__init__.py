"""
AWS资产收集模块

这个模块提供了完整的AWS资产收集功能，包括区域性服务和全局服务的资产收集。

主要功能：
- 计算资源收集（EC2、Lambda、ECS等）
- 网络资源收集（VPC、安全组、负载均衡器等）
- 存储资源收集（S3、EBS等）
- 数据库资源收集（RDS、DynamoDB等）
- 全局服务收集（CloudFront、WAF、ACM Global、Organizations等）
"""

from .collector import (
    AWSAssetCollector,
    collect_aws_assets_and_flows,
    collect_aws_assets_global,
    collect_aws_assets_complete
)

from .compute import ComputeAssetCollector
from .network import NetworkAssetCollector
from .storage import StorageAssetCollector
from .database import DatabaseAssetCollector
from .domain_router import DomainRouterAssetCollector
from .transit_gateway import TransitGatewayAssetCollector
from .iam import IAMAssetCollector

# 新增的全局服务collector
from .cloudfront import CloudFrontAssetCollector
from .waf import WAFAssetCollector
from .acm_global import ACMGlobalAssetCollector
from .organizations import OrganizationsAssetCollector


__all__ = [
    # 主要收集器
    'AWSAssetCollector',
    
    # 便捷函数
    'collect_aws_assets_and_flows',
    'collect_aws_assets_global', 
    'collect_aws_assets_complete',
    
    # 区域性服务collector
    'ComputeAssetCollector',
    'NetworkAssetCollector',
    'StorageAssetCollector',
    'DatabaseAssetCollector',
    'DomainRouterAssetCollector',
    'TransitGatewayAssetCollector',
    'IAMAssetCollector',
    
    # 全局服务collector
    'CloudFrontAssetCollector',
    'WAFAssetCollector',
    'ACMGlobalAssetCollector',
    'OrganizationsAssetCollector',

]
