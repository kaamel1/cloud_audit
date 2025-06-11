"""阿里云数据库资源处理模块，负责获取RDS、MongoDB、Redis等数据库资源信息。"""
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class DatabaseAssetCollector:
    """阿里云数据库资源收集器"""

    def __init__(self, session):
        """
        初始化数据库资源收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        # 初始化各个数据库服务的客户端
        self.rds_client = session.get_client('rds')
        self.mongodb_client = session.get_client('mongodb')
        self.redis_client = session.get_client('redis')
        self.polardb_client = session.get_client('polardb')
        self.hbase_client = session.get_client('hbase')
        self.clickhouse_client = session.get_client('clickhouse')

    def get_rds_instances(self) -> List[Dict[str, Any]]:
        """
        获取RDS实例信息

        Returns:
            List[Dict[str, Any]]: RDS实例列表
        """
        logger.info("获取RDS实例信息")
        logger.info(f"=== 开始获取区域 {self.session.region_id} 的RDS实例 ===")
        instances = []

        try:
            # 获取所有RDS实例
            from aliyunsdkrds.request.v20140815 import DescribeDBInstancesRequest
            import json
            
            request = DescribeDBInstancesRequest.DescribeDBInstancesRequest()
            request.set_accept_format('json')
            
            response = self.rds_client.do_action_with_exception(request)
            response_dict = json.loads(response)

            for instance in response_dict.get('Items', {}).get('DBInstance', []):
                instance_info = {
                    'DBInstanceId': instance.get('DBInstanceId'),
                    'DBInstanceDescription': instance.get('DBInstanceDescription'),
                    'Engine': instance.get('Engine'),
                    'EngineVersion': instance.get('EngineVersion'),
                    'DBInstanceStatus': instance.get('DBInstanceStatus'),
                    'DBInstanceClass': instance.get('DBInstanceClass'),
                    'ConnectionString': instance.get('ConnectionString'),
                    'Port': instance.get('Port'),
                    'ZoneId': instance.get('ZoneId'),
                    'VpcId': instance.get('VpcId'),
                    'VSwitchId': instance.get('VSwitchId'),
                    'CreateTime': instance.get('CreateTime'),
                    'ExpireTime': instance.get('ExpireTime'),
                    'PayType': instance.get('PayType'),
                    'ResourceGroupId': instance.get('ResourceGroupId'),
                }
                instances.append(instance_info)

            # 处理分页
            page_number = 1
            total_records = response_dict.get('TotalRecordCount', 0)
            page_size = response_dict.get('PageRecordCount', 0)
            
            while page_number * page_size < total_records:
                page_number += 1
                request = DescribeDBInstancesRequest.DescribeDBInstancesRequest()
                request.set_accept_format('json')
                request.set_PageNumber(page_number)
                
                response = self.rds_client.do_action_with_exception(request)
                response_dict = json.loads(response)

                for instance in response_dict.get('Items', {}).get('DBInstance', []):
                    instance_info = {
                        'DBInstanceId': instance.get('DBInstanceId'),
                        'DBInstanceDescription': instance.get('DBInstanceDescription'),
                        'Engine': instance.get('Engine'),
                        'EngineVersion': instance.get('EngineVersion'),
                        'DBInstanceStatus': instance.get('DBInstanceStatus'),
                        'DBInstanceClass': instance.get('DBInstanceClass'),
                        'ConnectionString': instance.get('ConnectionString'),
                        'Port': instance.get('Port'),
                        'ZoneId': instance.get('ZoneId'),
                        'VpcId': instance.get('VpcId'),
                        'VSwitchId': instance.get('VSwitchId'),
                        'CreateTime': instance.get('CreateTime'),
                        'ExpireTime': instance.get('ExpireTime'),
                        'PayType': instance.get('PayType'),
                        'ResourceGroupId': instance.get('ResourceGroupId'),
                    }
                    instances.append(instance_info)

        except Exception as e:
            logger.error(f"获取RDS实例信息失败: {str(e)}")

        return instances

    def get_mongodb_instances(self) -> List[Dict[str, Any]]:
        """
        获取MongoDB实例信息

        Returns:
            List[Dict[str, Any]]: MongoDB实例列表
        """
        logger.info("获取MongoDB实例信息")
        instances = []

        try:
            # 导入阿里云MongoDB SDK请求模块
            try:
                from aliyunsdkdds.request.v20151201 import DescribeDBInstancesRequest
                import json
            except ImportError:
                logger.warning(
                    "阿里云MongoDB SDK未安装，跳过MongoDB实例信息收集。\n"
                    "如需收集MongoDB数据，请安装：pip install aliyun-python-sdk-dds"
                )
                return instances
            
            # 获取所有MongoDB实例
            request = DescribeDBInstancesRequest.DescribeDBInstancesRequest()
            request.set_accept_format('json')
            
            response = self.mongodb_client.do_action_with_exception(request)
            response_dict = json.loads(response)

            for instance in response_dict.get('DBInstances', {}).get('DBInstance', []):
                instance_info = {
                    'DBInstanceId': instance.get('DBInstanceId'),
                    'DBInstanceDescription': instance.get('DBInstanceDescription'),
                    'DBInstanceStatus': instance.get('DBInstanceStatus'),
                    'DBInstanceClass': instance.get('DBInstanceClass'),
                    'Engine': instance.get('Engine'),
                    'EngineVersion': instance.get('EngineVersion'),
                    'NetworkType': instance.get('NetworkType'),
                    'VpcId': instance.get('VpcId'),
                    'VSwitchId': instance.get('VSwitchId'),
                    'ZoneId': instance.get('ZoneId'),
                    'ChargeType': instance.get('ChargeType'),
                    'CreationTime': instance.get('CreationTime'),
                    'RegionId': instance.get('RegionId'),
                    'ReplicationFactor': instance.get('ReplicationFactor'),
                    'ResourceGroupId': instance.get('ResourceGroupId'),
                }
                instances.append(instance_info)

            # 处理分页
            page_number = 1
            total_records = response_dict.get('TotalCount', 0)
            page_size = response_dict.get('PageSize', 30)  # 默认分页大小
            
            while page_number * page_size < total_records:
                page_number += 1
                request = DescribeDBInstancesRequest.DescribeDBInstancesRequest()
                request.set_accept_format('json')
                request.set_PageNumber(page_number)
                
                response = self.mongodb_client.do_action_with_exception(request)
                response_dict = json.loads(response)

                for instance in response_dict.get('DBInstances', {}).get('DBInstance', []):
                    instance_info = {
                        'DBInstanceId': instance.get('DBInstanceId'),
                        'DBInstanceDescription': instance.get('DBInstanceDescription'),
                        'DBInstanceStatus': instance.get('DBInstanceStatus'),
                        'DBInstanceClass': instance.get('DBInstanceClass'),
                        'Engine': instance.get('Engine'),
                        'EngineVersion': instance.get('EngineVersion'),
                        'NetworkType': instance.get('NetworkType'),
                        'VpcId': instance.get('VpcId'),
                        'VSwitchId': instance.get('VSwitchId'),
                        'ZoneId': instance.get('ZoneId'),
                        'ChargeType': instance.get('ChargeType'),
                        'CreationTime': instance.get('CreationTime'),
                        'RegionId': instance.get('RegionId'),
                        'ReplicationFactor': instance.get('ReplicationFactor'),
                        'ResourceGroupId': instance.get('ResourceGroupId'),
                    }
                    instances.append(instance_info)

        except Exception as e:
            logger.error(f"获取MongoDB实例信息失败: {str(e)}")

        return instances

    def get_redis_instances(self) -> List[Dict[str, Any]]:
        """
        获取Redis实例信息

        Returns:
            List[Dict[str, Any]]: Redis实例列表
        """
        logger.info("获取Redis实例信息")
        instances = []

        try:
            # 导入阿里云Redis SDK请求模块
            try:
                from aliyunsdkr_kvstore.request.v20150101 import DescribeInstancesRequest
                import json
            except ImportError:
                logger.warning(
                    "阿里云Redis SDK未安装，跳过Redis实例信息收集。\n"
                    "如需收集Redis数据，请安装：pip install aliyun-python-sdk-r-kvstore"
                )
                return instances
            
            # 获取所有Redis实例
            request = DescribeInstancesRequest.DescribeInstancesRequest()
            request.set_accept_format('json')
            
            response = self.redis_client.do_action_with_exception(request)
            response_dict = json.loads(response)

            for instance in response_dict.get('Instances', {}).get('KVStoreInstance', []):
                instance_info = {
                    'InstanceId': instance.get('InstanceId'),
                    'InstanceName': instance.get('InstanceName'),
                    'InstanceStatus': instance.get('InstanceStatus'),
                    'InstanceClass': instance.get('InstanceClass'),
                    'ArchitectureType': instance.get('ArchitectureType'),
                    'EngineVersion': instance.get('EngineVersion'),
                    'Bandwidth': instance.get('Bandwidth'),
                    'Connections': instance.get('Connections'),
                    'ConnectionDomain': instance.get('ConnectionDomain'),
                    'Port': instance.get('Port'),
                    'VpcId': instance.get('VpcId'),
                    'VSwitchId': instance.get('VSwitchId'),
                    'ZoneId': instance.get('ZoneId'),
                    'ChargeType': instance.get('ChargeType'),
                    'CreateTime': instance.get('CreateTime'),
                    'RegionId': instance.get('RegionId'),
                    'NetworkType': instance.get('NetworkType'),
                    'ResourceGroupId': instance.get('ResourceGroupId'),
                }
                instances.append(instance_info)

            # 处理分页
            page_number = 1
            total_records = response_dict.get('TotalCount', 0)
            page_size = response_dict.get('PageSize', 30)  # 默认分页大小
            
            while page_number * page_size < total_records:
                page_number += 1
                request = DescribeInstancesRequest.DescribeInstancesRequest()
                request.set_accept_format('json')
                request.set_PageNumber(page_number)
                
                response = self.redis_client.do_action_with_exception(request)
                response_dict = json.loads(response)

                for instance in response_dict.get('Instances', {}).get('KVStoreInstance', []):
                    instance_info = {
                        'InstanceId': instance.get('InstanceId'),
                        'InstanceName': instance.get('InstanceName'),
                        'InstanceStatus': instance.get('InstanceStatus'),
                        'InstanceClass': instance.get('InstanceClass'),
                        'ArchitectureType': instance.get('ArchitectureType'),
                        'EngineVersion': instance.get('EngineVersion'),
                        'Bandwidth': instance.get('Bandwidth'),
                        'Connections': instance.get('Connections'),
                        'ConnectionDomain': instance.get('ConnectionDomain'),
                        'Port': instance.get('Port'),
                        'VpcId': instance.get('VpcId'),
                        'VSwitchId': instance.get('VSwitchId'),
                        'ZoneId': instance.get('ZoneId'),
                        'ChargeType': instance.get('ChargeType'),
                        'CreateTime': instance.get('CreateTime'),
                        'RegionId': instance.get('RegionId'),
                        'NetworkType': instance.get('NetworkType'),
                        'ResourceGroupId': instance.get('ResourceGroupId'),
                    }
                    instances.append(instance_info)

        except Exception as e:
            logger.error(f"获取Redis实例信息失败: {str(e)}")

        return instances

    def get_all_database_assets(self) -> Dict[str, Any]:
        """
        获取所有数据库资产信息

        Returns:
            Dict[str, Any]: 所有数据库资产信息
        """
        logger.info("获取所有数据库资产信息")
        
        # 获取各类数据库实例
        rds_instances = self.get_rds_instances()
        mongodb_instances = self.get_mongodb_instances()
        redis_instances = self.get_redis_instances()
        
        # 整合所有数据库资产信息
        database_assets = {
            'rds': {instance['DBInstanceId']: instance for instance in rds_instances},
            'mongodb': {instance['DBInstanceId']: instance for instance in mongodb_instances},
            'redis': {instance['InstanceId']: instance for instance in redis_instances},
        }
        
        return database_assets