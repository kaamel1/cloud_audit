"""
腾讯云对象存储(COS)全局资产收集器

负责收集腾讯云的对象存储全局资源，包括：
- COS存储桶管理 - 全局服务（list_buckets可以返回所有区域存储桶）
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class COSGlobalAssetCollector:
    """COS全局资产收集器"""
    
    def __init__(self, session):
        """
        初始化COS全局资产收集器
        
        Args:
            session: 腾讯云会话对象
        """
        self.session = session
        
    def get_cos_buckets_global(self) -> List[Dict[str, Any]]:
        """
        获取COS存储桶列表（全局服务）
        
        注意：COS的list_buckets API可以一次性返回账户下所有区域的存储桶
        这与之前的实现不同，之前错误地按区域遍历
        
        Returns:
            List[Dict[str, Any]]: 所有区域的存储桶列表
        """
        logger.info("收集COS存储桶（全局）")
        buckets = []
        
        try:
            # 使用全局COS客户端，一次性获取所有区域的存储桶
            cos_client = self.session.get_client('cos')
            
            # COS的list_buckets API返回账户下所有区域的存储桶
            response = cos_client.list_buckets()
            logger.debug(f"COS list_buckets响应: {response}")
            
            # 安全地检查响应结构
            if response and isinstance(response, dict):
                buckets_data = response.get('Buckets')
                if buckets_data and isinstance(buckets_data, dict):
                    bucket_list = buckets_data.get('Bucket', [])
                    if bucket_list and isinstance(bucket_list, list):
                        for bucket in bucket_list:
                            if bucket and isinstance(bucket, dict):
                                bucket_info = {
                                    'bucket_name': bucket.get('Name', ''),
                                    'location': bucket.get('Location', ''),  # 存储桶所在区域
                                    'creation_date': bucket.get('CreationDate', ''),
                                    'type': 'cos_bucket'
                                }
                                buckets.append(bucket_info)
                    else:
                        logger.info("COS响应中没有存储桶数据或数据格式不正确")
                else:
                    logger.info("COS响应中没有Buckets字段或字段为空")
            else:
                logger.warning("COS list_buckets返回了空响应或格式不正确")
                    
        except Exception as e:
            logger.error(f"获取COS存储桶时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(buckets)} 个COS存储桶")
        return buckets
        
    def get_all_cos_global_assets(self) -> Dict[str, Dict[str, Any]]:
        """
        获取所有COS全局资源，按类型分开并返回单个资源项

        Returns:
            Dict[str, Dict[str, Any]]: 按类型分开的COS全局资源，每个资源项单独存储
        """
        logger.info("开始收集所有COS全局资源")
        
        buckets = {bucket.get('bucket_name', f'bucket_{i}'): bucket 
                  for i, bucket in enumerate(self.get_cos_buckets_global())}
        
        logger.info("COS全局资源收集完成")
        return {
            'cos_buckets': buckets
        } 