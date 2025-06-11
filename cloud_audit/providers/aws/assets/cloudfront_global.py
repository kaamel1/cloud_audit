"""
AWS CloudFront全局资源处理模块，负责获取CloudFront分发、源站等全球CDN全局资源信息。
CloudFront是AWS的全局服务，在不同区域获取到的数据是一致的。
"""
import boto3
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class CloudFrontGlobalAssetCollector:
    """AWS CloudFront全局资源收集器"""

    def __init__(self, session):
        """
        初始化CloudFront全局资源收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        self.cloudfront_client = session.get_client('cloudfront')

    def get_distributions(self) -> List[Dict[str, Any]]:
        """
        获取CloudFront分发信息

        Returns:
            List[Dict[str, Any]]: CloudFront分发列表
        """
        logger.info("获取CloudFront分发信息")
        distributions = []

        try:
            # 获取所有CloudFront分发
            next_marker = None
            while True:
                if next_marker:
                    response = self.cloudfront_client.list_distributions(Marker=next_marker)
                else:
                    response = self.cloudfront_client.list_distributions()
                
                for dist in response.get('DistributionList', {}).get('Items', []):
                    # 获取分发的详细配置
                    dist_detail = self.cloudfront_client.get_distribution(
                        Id=dist['Id']
                    )
                    
                    distribution_config = dist_detail['Distribution']
                    
                    # 获取分发的标签
                    tags = []
                    try:
                        tags_response = self.cloudfront_client.list_tags_for_resource(
                            Resource=distribution_config['ARN']
                        )
                        tags = tags_response.get('Tags', {}).get('Items', [])
                    except Exception as e:
                        logger.warning(f"获取分发 {dist['Id']} 标签失败: {str(e)}")

                    distribution_info = {
                        'Id': distribution_config.get('Id'),
                        'ARN': distribution_config.get('ARN'),
                        'Status': distribution_config.get('Status'),
                        'LastModifiedTime': distribution_config.get('LastModifiedTime'),
                        'DomainName': distribution_config.get('DomainName'),
                        'DistributionConfig': {
                            'CallerReference': distribution_config['DistributionConfig'].get('CallerReference'),
                            'Aliases': distribution_config['DistributionConfig'].get('Aliases', {}).get('Items', []),
                            'DefaultRootObject': distribution_config['DistributionConfig'].get('DefaultRootObject'),
                            'Comment': distribution_config['DistributionConfig'].get('Comment'),
                            'Enabled': distribution_config['DistributionConfig'].get('Enabled'),
                            'PriceClass': distribution_config['DistributionConfig'].get('PriceClass'),
                            'Origins': distribution_config['DistributionConfig'].get('Origins', {}).get('Items', []),
                            'DefaultCacheBehavior': distribution_config['DistributionConfig'].get('DefaultCacheBehavior'),
                            'CacheBehaviors': distribution_config['DistributionConfig'].get('CacheBehaviors', {}).get('Items', []),
                            'CustomErrorResponses': distribution_config['DistributionConfig'].get('CustomErrorResponses', {}).get('Items', []),
                            'ViewerCertificate': distribution_config['DistributionConfig'].get('ViewerCertificate'),
                            'WebACLId': distribution_config['DistributionConfig'].get('WebACLId'),
                            'HttpVersion': distribution_config['DistributionConfig'].get('HttpVersion'),
                            'IsIPV6Enabled': distribution_config['DistributionConfig'].get('IsIPV6Enabled'),
                            'Restrictions': distribution_config['DistributionConfig'].get('Restrictions'),
                            'Logging': distribution_config['DistributionConfig'].get('Logging')
                        },
                        'Tags': tags
                    }
                    distributions.append(distribution_info)
                
                if response.get('DistributionList', {}).get('IsTruncated'):
                    next_marker = response['DistributionList']['NextMarker']
                else:
                    break

        except Exception as e:
            logger.error(f"获取CloudFront分发信息失败: {str(e)}")

        return distributions

    def get_origin_access_identities(self) -> List[Dict[str, Any]]:
        """
        获取CloudFront原点访问身份信息

        Returns:
            List[Dict[str, Any]]: 原点访问身份列表
        """
        logger.info("获取CloudFront原点访问身份信息")
        identities = []

        try:
            next_marker = None
            while True:
                if next_marker:
                    response = self.cloudfront_client.list_cloud_front_origin_access_identities(Marker=next_marker)
                else:
                    response = self.cloudfront_client.list_cloud_front_origin_access_identities()
                
                for identity in response.get('CloudFrontOriginAccessIdentityList', {}).get('Items', []):
                    # 获取详细信息
                    identity_detail = self.cloudfront_client.get_cloud_front_origin_access_identity(
                        Id=identity['Id']
                    )
                    
                    identity_info = {
                        'Id': identity_detail['CloudFrontOriginAccessIdentity'].get('Id'),
                        'S3CanonicalUserId': identity_detail['CloudFrontOriginAccessIdentity'].get('S3CanonicalUserId'),
                        'CloudFrontOriginAccessIdentityConfig': identity_detail['CloudFrontOriginAccessIdentity'].get('CloudFrontOriginAccessIdentityConfig')
                    }
                    identities.append(identity_info)
                
                if response.get('CloudFrontOriginAccessIdentityList', {}).get('IsTruncated'):
                    next_marker = response['CloudFrontOriginAccessIdentityList']['NextMarker']
                else:
                    break

        except Exception as e:
            logger.error(f"获取CloudFront原点访问身份信息失败: {str(e)}")

        return identities

    def get_origin_access_controls(self) -> List[Dict[str, Any]]:
        """
        获取CloudFront原点访问控制信息

        Returns:
            List[Dict[str, Any]]: 原点访问控制列表
        """
        logger.info("获取CloudFront原点访问控制信息")
        access_controls = []

        try:
            # 获取原点访问控制列表
            next_marker = None
            while True:
                if next_marker:
                    response = self.cloudfront_client.list_origin_access_controls(Marker=next_marker)
                else:
                    response = self.cloudfront_client.list_origin_access_controls()
                
                for oac in response.get('OriginAccessControlList', {}).get('Items', []):
                    # 获取详细信息
                    oac_detail = self.cloudfront_client.get_origin_access_control(
                        Id=oac['Id']
                    )
                    
                    oac_info = {
                        'Id': oac_detail['OriginAccessControl'].get('Id'),
                        'OriginAccessControlConfig': oac_detail['OriginAccessControl'].get('OriginAccessControlConfig')
                    }
                    access_controls.append(oac_info)
                
                if response.get('OriginAccessControlList', {}).get('IsTruncated'):
                    next_marker = response['OriginAccessControlList']['NextMarker']
                else:
                    break

        except Exception as e:
            logger.error(f"获取CloudFront原点访问控制信息失败: {str(e)}")

        return access_controls

    def get_streaming_distributions(self) -> List[Dict[str, Any]]:
        """
        获取CloudFront流分发信息

        Returns:
            List[Dict[str, Any]]: 流分发列表
        """
        logger.info("获取CloudFront流分发信息")
        streaming_distributions = []

        try:
            next_marker = None
            while True:
                if next_marker:
                    response = self.cloudfront_client.list_streaming_distributions(Marker=next_marker)
                else:
                    response = self.cloudfront_client.list_streaming_distributions()
                
                for stream_dist in response.get('StreamingDistributionList', {}).get('Items', []):
                    # 获取流分发的详细配置
                    stream_detail = self.cloudfront_client.get_streaming_distribution(
                        Id=stream_dist['Id']
                    )
                    
                    streaming_config = stream_detail['StreamingDistribution']
                    
                    streaming_info = {
                        'Id': streaming_config.get('Id'),
                        'ARN': streaming_config.get('ARN'),
                        'Status': streaming_config.get('Status'),
                        'LastModifiedTime': streaming_config.get('LastModifiedTime'),
                        'DomainName': streaming_config.get('DomainName'),
                        'StreamingDistributionConfig': streaming_config.get('StreamingDistributionConfig')
                    }
                    streaming_distributions.append(streaming_info)
                
                if response.get('StreamingDistributionList', {}).get('IsTruncated'):
                    next_marker = response['StreamingDistributionList']['NextMarker']
                else:
                    break

        except Exception as e:
            logger.error(f"获取CloudFront流分发信息失败: {str(e)}")

        return streaming_distributions

    def get_cache_policies(self) -> List[Dict[str, Any]]:
        """
        获取CloudFront缓存策略信息

        Returns:
            List[Dict[str, Any]]: 缓存策略列表
        """
        logger.info("获取CloudFront缓存策略信息")
        cache_policies = []

        try:
            next_marker = None
            while True:
                if next_marker:
                    response = self.cloudfront_client.list_cache_policies(Marker=next_marker)
                else:
                    response = self.cloudfront_client.list_cache_policies()
                
                for policy in response.get('CachePolicyList', {}).get('Items', []):
                    # 获取策略详细信息
                    policy_detail = self.cloudfront_client.get_cache_policy(
                        Id=policy['CachePolicy']['Id']
                    )
                    
                    cache_policy_info = {
                        'Id': policy_detail['CachePolicy'].get('Id'),
                        'LastModifiedTime': policy_detail['CachePolicy'].get('LastModifiedTime'),
                        'CachePolicyConfig': policy_detail['CachePolicy'].get('CachePolicyConfig')
                    }
                    cache_policies.append(cache_policy_info)
                
                if response.get('CachePolicyList', {}).get('IsTruncated'):
                    next_marker = response['CachePolicyList']['NextMarker']
                else:
                    break

        except Exception as e:
            logger.error(f"获取CloudFront缓存策略信息失败: {str(e)}")

        return cache_policies

    def get_origin_request_policies(self) -> List[Dict[str, Any]]:
        """
        获取CloudFront原点请求策略信息

        Returns:
            List[Dict[str, Any]]: 原点请求策略列表
        """
        logger.info("获取CloudFront原点请求策略信息")
        origin_request_policies = []

        try:
            next_marker = None
            while True:
                if next_marker:
                    response = self.cloudfront_client.list_origin_request_policies(Marker=next_marker)
                else:
                    response = self.cloudfront_client.list_origin_request_policies()
                
                for policy in response.get('OriginRequestPolicyList', {}).get('Items', []):
                    # 获取策略详细信息
                    policy_detail = self.cloudfront_client.get_origin_request_policy(
                        Id=policy['OriginRequestPolicy']['Id']
                    )
                    
                    origin_request_policy_info = {
                        'Id': policy_detail['OriginRequestPolicy'].get('Id'),
                        'LastModifiedTime': policy_detail['OriginRequestPolicy'].get('LastModifiedTime'),
                        'OriginRequestPolicyConfig': policy_detail['OriginRequestPolicy'].get('OriginRequestPolicyConfig')
                    }
                    origin_request_policies.append(origin_request_policy_info)
                
                if response.get('OriginRequestPolicyList', {}).get('IsTruncated'):
                    next_marker = response['OriginRequestPolicyList']['NextMarker']
                else:
                    break

        except Exception as e:
            logger.error(f"获取CloudFront原点请求策略信息失败: {str(e)}")

        return origin_request_policies

    def get_all_cloudfront_global_assets(self) -> Dict[str, Any]:
        """
        获取所有CloudFront全局资源

        Returns:
            Dict[str, Any]: 所有CloudFront全局资源
        """
        logger.info("开始收集所有CloudFront全局资源")
        
        assets = {
            'distributions': self.get_distributions(),
            'origin_access_identities': self.get_origin_access_identities(),
            'origin_access_controls': self.get_origin_access_controls(),
            'streaming_distributions': self.get_streaming_distributions(),
            'cache_policies': self.get_cache_policies(),
            'origin_request_policies': self.get_origin_request_policies()
        }
        
        logger.info("CloudFront全局资源收集完成")
        return assets 