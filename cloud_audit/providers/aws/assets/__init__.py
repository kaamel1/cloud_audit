"""
AWS资产收集模块

这个模块提供了完整的AWS资产收集功能，包括区域性服务和全局服务的资产收集。

主要功能：
- 计算资源收集（EC2、Lambda、ECS等）
- 网络资源收集（VPC、安全组、负载均衡器等）
- 存储资源收集（S3、EBS等）
- 数据库资源收集（RDS、DynamoDB等）
- 全局服务收集（CloudFront、WAF、ACM Global、Organizations、IAM、Route53等）

使用方法：
- 区域性资产收集：使用 AWSAssetCollector 或 collect_aws_assets_and_flows
- 全局资产收集：使用 AWSGlobalAssetCollector 或 collect_aws_global_assets_and_flows
"""

# 区域性资产收集
from .collector import (
    AWSAssetCollector,
    collect_aws_assets_and_flows
)

# 全局资产收集
from .collector_global import (
    AWSGlobalAssetCollector,
    collect_aws_global_assets_and_flows,
    collect_aws_global_assets
)

# 区域性服务collector
from .compute import ComputeAssetCollector
from .network import NetworkAssetCollector
from .storage import StorageAssetCollector
from .database import DatabaseAssetCollector
from .transit_gateway import TransitGatewayAssetCollector

# 全局服务collector
from .cloudfront_global import CloudFrontGlobalAssetCollector
from .waf_global import WAFGlobalAssetCollector
from .acm_global import ACMGlobalAssetCollector
from .organizations_global import OrganizationsGlobalAssetCollector
from .iam_global import IAMGlobalAssetCollector
from .domain_router_global import DomainRouterGlobalAssetCollector

# 保留原有的collector供向后兼容
from .domain_router import DomainRouterAssetCollector
from .iam import IAMAssetCollector
from .cloudfront import CloudFrontAssetCollector
from .waf import WAFAssetCollector
from .organizations import OrganizationsAssetCollector


__all__ = [
    # 主要收集器
    'AWSAssetCollector',               # 区域性资产收集器
    'AWSGlobalAssetCollector',         # 全局资产收集器
    
    # 便捷函数
    'collect_aws_assets_and_flows',          # 区域性资产收集
    'collect_aws_global_assets_and_flows',   # 全局资产收集
    'collect_aws_global_assets',             # 全局资产收集（仅资产）
    
    # 区域性服务collector
    'ComputeAssetCollector',
    'NetworkAssetCollector',
    'StorageAssetCollector',
    'DatabaseAssetCollector',
    'TransitGatewayAssetCollector',
    
    # 全局服务collector（新）
    'CloudFrontGlobalAssetCollector',
    'WAFGlobalAssetCollector',
    'ACMGlobalAssetCollector',
    'OrganizationsGlobalAssetCollector',
    'IAMGlobalAssetCollector',
    'DomainRouterGlobalAssetCollector',
    
    # 保留原有collector供向后兼容
    'DomainRouterAssetCollector',
    'IAMAssetCollector',
    'CloudFrontAssetCollector',
    'WAFAssetCollector',
    'OrganizationsAssetCollector',
]
