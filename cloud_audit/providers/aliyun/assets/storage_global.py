"""阿里云存储资源处理模块，负责获取OSS、云盘等存储资源信息。"""
import logging
import json
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class StorageGlobalAssetCollector:
    """阿里云存储资源收集器"""

    def __init__(self, session):
        """
        初始化存储资源收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        self.ecs_client = session.get_client('ecs')  # 用于获取云盘信息
        # OSS客户端需要特殊处理，因为它使用的是专用SDK
        # self.oss_client 将在实际调用时创建

    def get_oss_buckets(self) -> List[Dict[str, Any]]:
        """
        获取OSS存储桶信息

        Returns:
            List[Dict[str, Any]]: OSS存储桶列表
        """
        logger.info("获取OSS存储桶信息")
        logger.info(f"=== 开始获取区域 {self.session.region_id} 的OSS存储桶 ===")
        buckets = []

        try:
            # 注意：OSS使用的是专用SDK，而不是通用的aliyunsdk模式
            # 这里需要使用OSS SDK的客户端
            import oss2
            
            # 创建OSS认证对象，需要处理STS token
            if hasattr(self.session, 'security_token') and self.session.security_token:
                # 使用STS临时凭证
                auth = oss2.StsAuth(
                    self.session.access_key_id, 
                    self.session.access_key_secret, 
                    self.session.security_token
                )
                logger.info("使用STS临时凭证创建OSS认证")
            else:
                # 使用永久凭证
                auth = oss2.Auth(self.session.access_key_id, self.session.access_key_secret)
                logger.info("使用永久凭证创建OSS认证")
            
            # 获取所有存储桶 - 使用当前区域的endpoint
            endpoint = f'http://oss-{self.session.region_id}.aliyuncs.com'
            logger.info(f"初始化OSS服务，使用endpoint: {endpoint}")
            service = oss2.Service(auth, endpoint)
            
            try:
                bucket_list = service.list_buckets()
                logger.info(f"成功获取OSS存储桶列表，共 {len(bucket_list.buckets)} 个存储桶")
            except oss2.exceptions.OssError as oe:
                logger.error(f"获取OSS存储桶列表失败 (OSS错误): {oe}")
                return buckets
            except Exception as e:
                logger.error(f"获取OSS存储桶列表失败: {e}")
                return buckets
            
            # 处理存储桶数据
            for bucket_info in bucket_list.buckets:
                bucket_name = bucket_info.name
                bucket_location = bucket_info.location  # 存储桶实际所在的区域
                
                # 为存储桶使用正确的区域endpoint
                # 处理bucket_location格式，确保不重复oss-前缀
                if bucket_location.startswith('oss-'):
                    region_endpoint = f'http://{bucket_location}.aliyuncs.com'
                else:
                    region_endpoint = f'http://oss-{bucket_location}.aliyuncs.com'
                logger.debug(f"存储桶 {bucket_name} 位置: {bucket_location}, 使用endpoint: {region_endpoint}")
                
                # 创建Bucket对象，使用区域endpoint
                region_bucket = oss2.Bucket(auth, region_endpoint, bucket_name)
                
                # 获取存储桶元数据
                bucket_meta = {}
                try:
                    bucket_meta = region_bucket.get_bucket_info()
                    logger.debug(f"成功获取存储桶 {bucket_name} 元数据")
                except oss2.exceptions.OssError as oe:
                    logger.warning(f"获取存储桶 {bucket_name} 元数据失败 (OSS错误): {oe}")
                except Exception as e:
                    # 特别处理DNS解析错误
                    error_msg = str(e) if hasattr(e, '__str__') else repr(e)
                    if 'Failed to resolve' in error_msg or 'NameResolutionError' in error_msg:
                        logger.error(f"存储桶 {bucket_name} DNS解析失败，可能是endpoint构建错误: {error_msg}")
                        logger.error(f"存储桶 {bucket_name} 使用的endpoint: {region_endpoint}")
                    else:
                        logger.warning(f"获取存储桶 {bucket_name} 元数据失败: {error_msg}")
                
                # 获取存储桶ACL
                bucket_acl = {}
                try:
                    bucket_acl = region_bucket.get_bucket_acl()
                    logger.debug(f"成功获取存储桶 {bucket_name} ACL")
                except oss2.exceptions.OssError as oe:
                    logger.warning(f"获取存储桶 {bucket_name} ACL失败 (OSS错误): {oe}")
                except Exception as e:
                    # 特别处理DNS解析错误
                    error_msg = str(e) if hasattr(e, '__str__') else repr(e)
                    if 'Failed to resolve' in error_msg or 'NameResolutionError' in error_msg:
                        logger.error(f"存储桶 {bucket_name} DNS解析失败，可能是endpoint构建错误: {error_msg}")
                        logger.error(f"存储桶 {bucket_name} 使用的endpoint: {region_endpoint}")
                    else:
                        logger.warning(f"获取存储桶 {bucket_name} ACL失败: {error_msg}")
                
                # 获取存储桶CORS跨域配置
                bucket_cors = {}
                try:
                    cors_result = region_bucket.get_bucket_cors()
                    bucket_cors = {
                        'rules': []
                    }
                    # 处理CORS规则
                    if hasattr(cors_result, 'rules') and cors_result.rules:
                        for rule in cors_result.rules:
                            rule_info = {
                                'allowed_origins': getattr(rule, 'allowed_origins', []),
                                'allowed_methods': getattr(rule, 'allowed_methods', []),
                                'allowed_headers': getattr(rule, 'allowed_headers', []),
                                'expose_headers': getattr(rule, 'expose_headers', []),
                                'max_age_seconds': getattr(rule, 'max_age_seconds', None)
                            }
                            bucket_cors['rules'].append(rule_info)
                    logger.debug(f"成功获取存储桶 {bucket_name} CORS配置")
                except oss2.exceptions.NoSuchCors:
                    # 没有设置CORS配置，这是正常情况
                    bucket_cors = {'rules': [], 'note': 'No CORS configuration set'}
                    logger.debug(f"存储桶 {bucket_name} 未设置CORS配置")
                except oss2.exceptions.OssError as oe:
                    logger.warning(f"获取存储桶 {bucket_name} CORS配置失败 (OSS错误): {oe}")
                    bucket_cors = {'error': str(oe)}
                except Exception as e:
                    # 特别处理DNS解析错误
                    error_msg = str(e) if hasattr(e, '__str__') else repr(e)
                    if 'Failed to resolve' in error_msg or 'NameResolutionError' in error_msg:
                        logger.error(f"存储桶 {bucket_name} DNS解析失败，可能是endpoint构建错误: {error_msg}")
                        logger.error(f"存储桶 {bucket_name} 使用的endpoint: {region_endpoint}")
                    else:
                        logger.warning(f"获取存储桶 {bucket_name} CORS配置失败: {error_msg}")
                    bucket_cors = {'error': error_msg}
                
                # 获取存储桶静态网站托管配置（自定义域名配置）
                bucket_website = {}
                try:
                    website_result = region_bucket.get_bucket_website()
                    bucket_website = {
                        'index_file': getattr(website_result, 'index_file', None),
                        'error_file': getattr(website_result, 'error_file', None),
                        'enabled': True
                    }
                    logger.debug(f"成功获取存储桶 {bucket_name} 静态网站托管配置")
                except oss2.exceptions.NoSuchWebsite:
                    # 没有设置静态网站托管配置，这是正常情况
                    bucket_website = {'enabled': False, 'note': 'No website configuration set'}
                    logger.debug(f"存储桶 {bucket_name} 未设置静态网站托管配置")
                except oss2.exceptions.OssError as oe:
                    logger.warning(f"获取存储桶 {bucket_name} 静态网站托管配置失败 (OSS错误): {oe}")
                    bucket_website = {'error': str(oe)}
                except Exception as e:
                    # 特别处理DNS解析错误
                    error_msg = str(e) if hasattr(e, '__str__') else repr(e)
                    if 'Failed to resolve' in error_msg or 'NameResolutionError' in error_msg:
                        logger.error(f"存储桶 {bucket_name} DNS解析失败，可能是endpoint构建错误: {error_msg}")
                        logger.error(f"存储桶 {bucket_name} 使用的endpoint: {region_endpoint}")
                    else:
                        logger.warning(f"获取存储桶 {bucket_name} 静态网站托管配置失败: {error_msg}")
                    bucket_website = {'error': error_msg}
                
                # 获取存储桶防盗链配置
                bucket_referer = {}
                try:
                    referer_result = region_bucket.get_bucket_referer()
                    bucket_referer = {
                        'allow_empty_referer': getattr(referer_result, 'allow_empty_referer', None),
                        'referers': getattr(referer_result, 'referers', []),
                        'allow_truncate_query_string': getattr(referer_result, 'allow_truncate_query_string', None),
                        'truncate_path': getattr(referer_result, 'truncate_path', None),
                        'enabled': True
                    }
                    # 处理黑名单referer（如果存在）
                    if hasattr(referer_result, 'black_referers'):
                        bucket_referer['black_referers'] = getattr(referer_result, 'black_referers', [])
                    logger.debug(f"成功获取存储桶 {bucket_name} 防盗链配置")
                except oss2.exceptions.OssError as oe:
                    logger.warning(f"获取存储桶 {bucket_name} 防盗链配置失败 (OSS错误): {oe}")
                    bucket_referer = {'error': str(oe)}
                except Exception as e:
                    # 特别处理DNS解析错误
                    error_msg = str(e) if hasattr(e, '__str__') else repr(e)
                    if 'Failed to resolve' in error_msg or 'NameResolutionError' in error_msg:
                        logger.error(f"存储桶 {bucket_name} DNS解析失败，可能是endpoint构建错误: {error_msg}")
                        logger.error(f"存储桶 {bucket_name} 使用的endpoint: {region_endpoint}")
                    else:
                        logger.warning(f"获取存储桶 {bucket_name} 防盗链配置失败: {error_msg}")
                    bucket_referer = {'error': error_msg}
                
                # 获取存储桶HTTPS配置信息（通过检查endpoint协议）
                bucket_https = {
                    'endpoint_supports_https': region_endpoint.replace('http://', 'https://') if region_endpoint.startswith('http://') else region_endpoint,
                    'current_endpoint_protocol': 'https' if region_endpoint.startswith('https://') else 'http',
                    'https_available': True,  # OSS 支持 HTTPS
                    'note': 'HTTPS is supported by OSS. Current endpoint protocol depends on client configuration.'
                }
                
                # 获取存储桶CNAME自定义域名配置
                bucket_cname = {}
                try:
                    cname_result = region_bucket.list_bucket_cname()
                    bucket_cname = {
                        'custom_domains': [],
                        'enabled': False
                    }
                    # 处理CNAME配置
                    if hasattr(cname_result, 'cname') and cname_result.cname:
                        bucket_cname['enabled'] = True
                        for cname_info in cname_result.cname:
                            domain_info = {
                                'domain': getattr(cname_info, 'domain', None),
                                'last_modified': getattr(cname_info, 'last_modified', None),
                                'status': getattr(cname_info, 'status', None),
                                'is_purge_cdn_cache': getattr(cname_info, 'is_purge_cdn_cache', None)
                            }
                            # 处理证书信息（如果存在）
                            if hasattr(cname_info, 'certificate') and cname_info.certificate:
                                cert = cname_info.certificate
                                domain_info['certificate'] = {
                                    'cert_id': getattr(cert, 'cert_id', None),
                                    'type': getattr(cert, 'type', None),
                                    'status': getattr(cert, 'status', None),
                                    'creation_date': getattr(cert, 'creation_date', None),
                                    'fingerprint': getattr(cert, 'fingerprint', None),
                                    'valid_start_date': getattr(cert, 'valid_start_date', None),
                                    'valid_end_date': getattr(cert, 'valid_end_date', None)
                                }
                            else:
                                domain_info['certificate'] = None
                            bucket_cname['custom_domains'].append(domain_info)
                    else:
                        bucket_cname['note'] = 'No CNAME configuration set'
                    logger.debug(f"成功获取存储桶 {bucket_name} CNAME配置")
                except oss2.exceptions.OssError as oe:
                    logger.warning(f"获取存储桶 {bucket_name} CNAME配置失败 (OSS错误): {oe}")
                    bucket_cname = {'error': str(oe)}
                except Exception as e:
                    # 特别处理DNS解析错误
                    error_msg = str(e) if hasattr(e, '__str__') else repr(e)
                    if 'Failed to resolve' in error_msg or 'NameResolutionError' in error_msg:
                        logger.error(f"存储桶 {bucket_name} DNS解析失败，可能是endpoint构建错误: {error_msg}")
                        logger.error(f"存储桶 {bucket_name} 使用的endpoint: {region_endpoint}")
                    else:
                        logger.warning(f"获取存储桶 {bucket_name} CNAME配置失败: {error_msg}")
                    bucket_cname = {'error': error_msg}
                
                # 构建存储桶信息
                bucket_data = {
                    'BucketName': bucket_name,
                    'CreationDate': bucket_info.creation_date,
                    'Location': bucket_location,
                    'StorageClass': getattr(bucket_info, 'storage_class', None),
                    'ExtranetEndpoint': getattr(bucket_meta, 'extranet_endpoint', None),
                    'IntranetEndpoint': getattr(bucket_meta, 'intranet_endpoint', None),
                    'ACL': getattr(bucket_acl, 'acl', None),
                    'CORS': bucket_cors,
                    'Website': bucket_website,
                    'Referer': bucket_referer,
                    'HTTPS': bucket_https,
                    'CNAME': bucket_cname,
                    'Endpoint': region_endpoint,  # 记录使用的endpoint
                }
                buckets.append(bucket_data)
                
        except ImportError as e:
            logger.error(f"导入OSS SDK失败: {str(e)}")
        except Exception as e:
            logger.error(f"获取OSS存储桶信息失败: {str(e)}")
        
        return buckets

    def get_all_storage_global_assets(self) -> Dict[str, Any]:
        """
        获取所有存储资源

        Returns:
            Dict[str, Any]: 所有存储资源
        """
        logger.info("获取所有阿里云存储资源")
        
        # 获取各类存储资源
        oss_buckets = self.get_oss_buckets()
        
        # 组织返回结果
        storage_assets = {
            'oss': {bucket['BucketName']: bucket for bucket in oss_buckets},
        }
        
        logger.info(f"已获取 {len(oss_buckets)} 个OSS存储桶")
        return storage_assets