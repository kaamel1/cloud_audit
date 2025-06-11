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
        disks = self.get_disks()
        
        # 组织返回结果
        storage_assets = {
            'disks': {disk['DiskId']: disk for disk in disks},
        }
        
        logger.info(f"已获取 {len(disks)} 个云盘")
        return storage_assets