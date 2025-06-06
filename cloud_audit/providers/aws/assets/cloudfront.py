"""
AWS CloudFront资源处理模块，负责获取CloudFront分发、源站等全球CDN资源信息。
"""
import boto3
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class CloudFrontAssetCollector:
    """AWS CloudFront资源收集器"""

    def __init__(self, session):
        """
        初始化CloudFront资源收集器

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
            paginator = self.cloudfront_client.get_paginator('list_distributions')
            
            for page in paginator.paginate():
                for dist in page.get('DistributionList', {}).get('Items', []):
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
            paginator = self.cloudfront_client.get_paginator('list_cloud_front_origin_access_identities')
            
            for page in paginator.paginate():
                for identity in page.get('CloudFrontOriginAccessIdentityList', {}).get('Items', []):
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

        except Exception as e:
            logger.error(f"获取CloudFront原点访问身份信息失败: {str(e)}")

        return identities

    def get_invalidations(self) -> List[Dict[str, Any]]:
        """
        获取CloudFront失效信息

        Returns:
            List[Dict[str, Any]]: 失效列表
        """
        logger.info("获取CloudFront失效信息")
        all_invalidations = []

        try:
            # 首先获取所有分发
            distributions = self.get_distributions()
            
            for dist in distributions:
                dist_id = dist['Id']
                try:
                    paginator = self.cloudfront_client.get_paginator('list_invalidations')
                    
                    for page in paginator.paginate(DistributionId=dist_id):
                        for invalidation in page.get('InvalidationList', {}).get('Items', []):
                            invalidation_info = {
                                'DistributionId': dist_id,
                                'Id': invalidation.get('Id'),
                                'Status': invalidation.get('Status'),
                                'CreateTime': invalidation.get('CreateTime'),
                                'InvalidationBatch': invalidation.get('InvalidationBatch')
                            }
                            all_invalidations.append(invalidation_info)
                            
                except Exception as e:
                    logger.warning(f"获取分发 {dist_id} 的失效信息失败: {str(e)}")

        except Exception as e:
            logger.error(f"获取CloudFront失效信息失败: {str(e)}")

        return all_invalidations

    def get_streaming_distributions(self) -> List[Dict[str, Any]]:
        """
        获取CloudFront流分发信息

        Returns:
            List[Dict[str, Any]]: 流分发列表
        """
        logger.info("获取CloudFront流分发信息")
        streaming_distributions = []

        try:
            paginator = self.cloudfront_client.get_paginator('list_streaming_distributions')
            
            for page in paginator.paginate():
                for stream_dist in page.get('StreamingDistributionList', {}).get('Items', []):
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

        except Exception as e:
            logger.error(f"获取CloudFront流分发信息失败: {str(e)}")

        return streaming_distributions

    def get_all_cloudfront_assets(self) -> Dict[str, Any]:
        """
        获取所有CloudFront资源

        Returns:
            Dict[str, Any]: 所有CloudFront资源
        """
        logger.info("获取所有CloudFront资源")
        
        distributions = self.get_distributions()
        origin_access_identities = self.get_origin_access_identities()
        invalidations = self.get_invalidations()
        streaming_distributions = self.get_streaming_distributions()
        
        cloudfront_assets = {
            'distributions': {dist['Id']: dist for dist in distributions},
            'origin_access_identities': {oai['Id']: oai for oai in origin_access_identities},
            'invalidations': invalidations,  # 保持列表格式，因为可能有重复的分发ID
            'streaming_distributions': {stream['Id']: stream for stream in streaming_distributions}
        }
        
        logger.info(f"已获取 {len(distributions)} 个CloudFront分发, {len(origin_access_identities)} 个原点访问身份, {len(invalidations)} 个失效记录, {len(streaming_distributions)} 个流分发")
        return cloudfront_assets 