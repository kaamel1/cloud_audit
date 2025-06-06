"""
AWS存储资源处理模块，负责获取S3、EBS等存储资源信息。
"""
import boto3
import logging
import time
from typing import Dict, List, Any
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class StorageAssetCollector:
    """AWS存储资源收集器"""

    def __init__(self, session):
        """
        初始化存储资源收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        self.s3_client = session.get_client('s3')
        self.ec2_client = session.get_client('ec2')

    def _safe_s3_operation(self, operation_func, operation_name, bucket_name, max_retries=1):
        """
        安全执行S3操作，带重试机制
        
        Args:
            operation_func: 要执行的操作函数
            operation_name: 操作名称（用于日志）
            bucket_name: 存储桶名称
            max_retries: 最大重试次数
            
        Returns:
            操作结果，失败时返回None
        """
        for attempt in range(max_retries + 1):
            try:
                ret =  operation_func()
                logger.warning(f"获取存储桶 {bucket_name} {operation_name} 成功")
                return ret
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code')
                if error_code == 'InvalidToken':
                    if attempt < max_retries:
                        logger.warning(f"获取存储桶 {bucket_name} {operation_name}失败: InvalidToken，1秒后重试...")
                        time.sleep(1)
                        continue
                    else:
                        logger.error(f"获取存储桶 {bucket_name} {operation_name}失败: AWS token无效或已过期，已重试{max_retries}次")
                else:
                    logger.warning(f"获取存储桶 {bucket_name} {operation_name}失败: {str(e)}")
                return None
            except Exception as e:
                logger.warning(f"获取存储桶 {bucket_name} {operation_name}失败: {str(e)}")
                return None

    def get_s3_buckets(self) -> List[Dict[str, Any]]:
        """
        获取S3存储桶信息

        Returns:
            List[Dict[str, Any]]: S3存储桶列表
        """
        logger.info("获取S3存储桶信息")
        buckets = []

        try:
            # 获取所有S3存储桶
            response = self.s3_client.list_buckets()

            for bucket in response.get('Buckets', []):
                bucket_name = bucket.get('Name')

                # 获取存储桶位置
                location = self._safe_s3_operation(
                    lambda: self.s3_client.get_bucket_location(Bucket=bucket_name).get('LocationConstraint'),
                    "位置",
                    bucket_name
                )

                if location != self.session.boto3_session.region_name:
                    logger.warning(f"获取存储桶 {bucket_name} 位置非当前区域: {location} != {self.session.boto3_session.region_name}")
                    continue

                # 获取存储桶策略
                policy = self._safe_s3_operation(
                    lambda: self.s3_client.get_bucket_policy(Bucket=bucket_name).get('Policy'),
                    "策略", 
                    bucket_name
                )

                # 获取存储桶ACL
                acl = self._safe_s3_operation(
                    lambda: self.s3_client.get_bucket_acl(Bucket=bucket_name),
                    "ACL",
                    bucket_name
                )

                bucket_info = {
                    'Name': bucket_name,
                    'CreationDate': bucket.get('CreationDate'),
                    'Location': location,
                    'Policy': policy,
                    'ACL': acl,
                }
                buckets.append(bucket_info)

        except Exception as e:
            logger.error(f"获取S3存储桶信息失败: {str(e)}")

        return buckets

    def get_ebs_volumes(self) -> List[Dict[str, Any]]:
        """
        获取EBS卷信息

        Returns:
            List[Dict[str, Any]]: EBS卷列表
        """
        logger.info("获取EBS卷信息")
        volumes = []

        try:
            # 获取所有EBS卷
            response = self.ec2_client.describe_volumes()

            for volume in response.get('Volumes', []):
                volume_info = {
                    'VolumeId': volume.get('VolumeId'),
                    'Size': volume.get('Size'),
                    'VolumeType': volume.get('VolumeType'),
                    'State': volume.get('State'),
                    'CreateTime': volume.get('CreateTime'),
                    'AvailabilityZone': volume.get('AvailabilityZone'),
                    'Encrypted': volume.get('Encrypted'),
                    'KmsKeyId': volume.get('KmsKeyId'),
                    'Attachments': volume.get('Attachments', []),
                    'Tags': volume.get('Tags', []),
                }
                volumes.append(volume_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_volumes(
                    NextToken=response['NextToken']
                )

                for volume in response.get('Volumes', []):
                    volume_info = {
                        'VolumeId': volume.get('VolumeId'),
                        'Size': volume.get('Size'),
                        'VolumeType': volume.get('VolumeType'),
                        'State': volume.get('State'),
                        'CreateTime': volume.get('CreateTime'),
                        'AvailabilityZone': volume.get('AvailabilityZone'),
                        'Encrypted': volume.get('Encrypted'),
                        'KmsKeyId': volume.get('KmsKeyId'),
                        'Attachments': volume.get('Attachments', []),
                        'Tags': volume.get('Tags', []),
                    }
                    volumes.append(volume_info)

        except Exception as e:
            logger.error(f"获取EBS卷信息失败: {str(e)}")

        return volumes

    def get_all_storage_assets(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        获取所有存储资源，按类型分开并返回单个资源项

        Returns:
            Dict[str, Dict[str, Dict[str, Any]]]: 按类型分开的存储资源，每个资源项单独存储
        """
        s3_buckets = {bucket['Name']: bucket for bucket in self.get_s3_buckets()}
        ebs_volumes = {volume['VolumeId']: volume for volume in self.get_ebs_volumes()}
        
        return {
            's3': s3_buckets,
            'ebs': ebs_volumes
        }
