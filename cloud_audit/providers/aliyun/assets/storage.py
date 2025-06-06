"""阿里云存储资源处理模块，负责获取OSS、云盘等存储资源信息。"""
import logging
import json
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class StorageAssetCollector:
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
                
                # 构建存储桶信息
                bucket_data = {
                    'BucketName': bucket_name,
                    'CreationDate': bucket_info.creation_date,
                    'Location': bucket_location,
                    'StorageClass': getattr(bucket_info, 'storage_class', None),
                    'ExtranetEndpoint': getattr(bucket_meta, 'extranet_endpoint', None),
                    'IntranetEndpoint': getattr(bucket_meta, 'intranet_endpoint', None),
                    'ACL': getattr(bucket_acl, 'acl', None),
                    'Endpoint': region_endpoint,  # 记录使用的endpoint
                }
                buckets.append(bucket_data)
                
        except ImportError as e:
            logger.error(f"导入OSS SDK失败: {str(e)}")
        except Exception as e:
            logger.error(f"获取OSS存储桶信息失败: {str(e)}")
        
        return buckets

    def get_disks(self) -> List[Dict[str, Any]]:
        """
        获取云盘信息

        Returns:
            List[Dict[str, Any]]: 云盘列表
        """
        logger.info("获取云盘信息")
        disks = []

        try:
            # 导入阿里云ECS SDK请求模块
            from aliyunsdkecs.request.v20140526 import DescribeDisksRequest
            
            # 创建请求对象
            request = DescribeDisksRequest.DescribeDisksRequest()
            request.set_accept_format('json')
            
            # 设置分页参数
            page_size = 100
            request.set_PageSize(page_size)
            
            # 分页获取所有云盘
            page_number = 1
            total_disks = []
            
            while True:
                request.set_PageNumber(page_number)
                response = self.ecs_client.do_action_with_exception(request)
                response_json = json.loads(response)
                
                current_disks = response_json.get('Disks', {}).get('Disk', [])
                total_disks.extend(current_disks)
                
                # 判断是否还有更多页
                total_count = response_json.get('TotalCount', 0)
                if page_number * page_size >= total_count:
                    break
                    
                page_number += 1
            
            # 处理云盘数据
            for disk in total_disks:
                disk_info = {
                    'DiskId': disk.get('DiskId'),
                    'DiskName': disk.get('DiskName'),
                    'Size': disk.get('Size'),
                    'Category': disk.get('Category'),
                    'Status': disk.get('Status'),
                    'Type': disk.get('Type'),
                    'InstanceId': disk.get('InstanceId'),
                    'CreationTime': disk.get('CreationTime'),
                    'RegionId': disk.get('RegionId'),
                    'ZoneId': disk.get('ZoneId'),
                    'Encrypted': disk.get('Encrypted'),
                    'DeleteWithInstance': disk.get('DeleteWithInstance'),
                    'Tags': disk.get('Tags', {}).get('Tag', []),
                }
                disks.append(disk_info)
                
        except Exception as e:
            logger.error(f"获取云盘信息失败: {str(e)}")
        
        return disks

    def get_all_storage_assets(self) -> Dict[str, Any]:
        """
        获取所有存储资源

        Returns:
            Dict[str, Any]: 所有存储资源
        """
        logger.info("获取所有阿里云存储资源")
        
        # 获取各类存储资源
        oss_buckets = self.get_oss_buckets()
        disks = self.get_disks()
        
        # 组织返回结果
        storage_assets = {
            'oss': {bucket['BucketName']: bucket for bucket in oss_buckets},
            'disks': {disk['DiskId']: disk for disk in disks},
        }
        
        logger.info(f"已获取 {len(oss_buckets)} 个OSS存储桶, {len(disks)} 个云盘")
        return storage_assets