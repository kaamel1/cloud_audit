"""
AWS数据库资源处理模块，负责获取RDS、DynamoDB、DocumentDB、MemoryDB、Neptune、Timestream等数据库资源信息。
"""
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class DatabaseAssetCollector:
    """AWS数据库资源收集器"""

    def __init__(self, session):
        """
        初始化数据库资源收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        self.rds_client = session.get_client('rds')
        self.dynamodb_client = session.get_client('dynamodb')
        self.docdb_client = session.get_client('docdb')
        self.memorydb_client = session.get_client('memorydb')
        self.neptune_client = self.rds_client  # Neptune使用RDS API
        self.timestream_client = session.get_client('timestream-write')
        self.keyspaces_client = session.get_client('keyspaces')
        self.opensearch_client = session.get_client('opensearch')  # 原ElasticSearch服务
        self.elasticache_client = session.get_client('elasticache')  # ElastiCache服务

    def get_rds_instances(self) -> List[Dict[str, Any]]:
        """
        获取RDS实例信息

        Returns:
            List[Dict[str, Any]]: RDS实例列表
        """
        logger.info("获取RDS实例信息")
        instances = []

        try:
            # 获取所有RDS实例
            response = self.rds_client.describe_db_instances()

            for instance in response.get('DBInstances', []):
                instance_info = {
                    'DBInstanceIdentifier': instance.get('DBInstanceIdentifier'),
                    'DBInstanceClass': instance.get('DBInstanceClass'),
                    'Engine': instance.get('Engine'),
                    'EngineVersion': instance.get('EngineVersion'),
                    'DBInstanceStatus': instance.get('DBInstanceStatus'),
                    'MasterUsername': instance.get('MasterUsername'),
                    'Endpoint': instance.get('Endpoint'),
                    'AllocatedStorage': instance.get('AllocatedStorage'),
                    'InstanceCreateTime': instance.get('InstanceCreateTime'),
                    'VpcSecurityGroups': instance.get('VpcSecurityGroups', []),
                    'DBSubnetGroup': instance.get('DBSubnetGroup'),
                    'MultiAZ': instance.get('MultiAZ'),
                    'PubliclyAccessible': instance.get('PubliclyAccessible'),
                    'StorageEncrypted': instance.get('StorageEncrypted'),
                }
                instances.append(instance_info)

            # 处理分页
            while 'Marker' in response:
                response = self.rds_client.describe_db_instances(
                    Marker=response['Marker']
                )

                for instance in response.get('DBInstances', []):
                    instance_info = {
                        'DBInstanceIdentifier': instance.get('DBInstanceIdentifier'),
                        'DBInstanceClass': instance.get('DBInstanceClass'),
                        'Engine': instance.get('Engine'),
                        'EngineVersion': instance.get('EngineVersion'),
                        'DBInstanceStatus': instance.get('DBInstanceStatus'),
                        'MasterUsername': instance.get('MasterUsername'),
                        'Endpoint': instance.get('Endpoint'),
                        'AllocatedStorage': instance.get('AllocatedStorage'),
                        'InstanceCreateTime': instance.get('InstanceCreateTime'),
                        'VpcSecurityGroups': instance.get('VpcSecurityGroups', []),
                        'DBSubnetGroup': instance.get('DBSubnetGroup'),
                        'MultiAZ': instance.get('MultiAZ'),
                        'PubliclyAccessible': instance.get('PubliclyAccessible'),
                        'StorageEncrypted': instance.get('StorageEncrypted'),
                    }
                    instances.append(instance_info)

        except Exception as e:
            logger.error(f"获取RDS实例信息失败: {str(e)}")

        return instances

    def get_dynamodb_tables(self) -> List[Dict[str, Any]]:
        """
        获取DynamoDB表信息

        Returns:
            List[Dict[str, Any]]: DynamoDB表列表
        """
        logger.info("获取DynamoDB表信息")
        tables = []

        try:
            # 获取所有DynamoDB表
            response = self.dynamodb_client.list_tables()
            
            table_names = response.get('TableNames', [])
            
            for table_name in table_names:
                # 获取表详细信息
                table_details = self.dynamodb_client.describe_table(TableName=table_name)
                table_info = table_details.get('Table', {})
                tables.append(table_info)
                
            # 处理分页
            while 'LastEvaluatedTableName' in response:
                response = self.dynamodb_client.list_tables(
                    ExclusiveStartTableName=response['LastEvaluatedTableName']
                )
                
                table_names = response.get('TableNames', [])
                
                for table_name in table_names:
                    # 获取表详细信息
                    table_details = self.dynamodb_client.describe_table(TableName=table_name)
                    table_info = table_details.get('Table', {})
                    tables.append(table_info)

        except Exception as e:
            logger.error(f"获取DynamoDB表信息失败: {str(e)}")

        return tables

    def get_documentdb_clusters(self) -> List[Dict[str, Any]]:
        """
        获取DocumentDB集群信息

        Returns:
            List[Dict[str, Any]]: DocumentDB集群列表
        """
        logger.info("获取DocumentDB集群信息")
        clusters = []

        try:
            # 获取所有DocumentDB集群
            response = self.docdb_client.describe_db_clusters(
                Filters=[{'Name': 'engine', 'Values': ['docdb']}]
            )

            for cluster in response.get('DBClusters', []):
                cluster_info = {
                    'DBClusterIdentifier': cluster.get('DBClusterIdentifier'),
                    'Status': cluster.get('Status'),
                    'Engine': cluster.get('Engine'),
                    'EngineVersion': cluster.get('EngineVersion'),
                    'DBClusterMembers': cluster.get('DBClusterMembers', []),
                    'VpcSecurityGroups': cluster.get('VpcSecurityGroups', []),
                    'DBSubnetGroup': cluster.get('DBSubnetGroup'),
                    'Endpoint': cluster.get('Endpoint'),
                    'ReaderEndpoint': cluster.get('ReaderEndpoint'),
                    'MultiAZ': cluster.get('MultiAZ'),
                    'StorageEncrypted': cluster.get('StorageEncrypted'),
                }
                clusters.append(cluster_info)

            # 处理分页
            while 'Marker' in response:
                response = self.docdb_client.describe_db_clusters(
                    Marker=response['Marker'],
                    Filters=[{'Name': 'engine', 'Values': ['docdb']}]
                )

                for cluster in response.get('DBClusters', []):
                    cluster_info = {
                        'DBClusterIdentifier': cluster.get('DBClusterIdentifier'),
                        'Status': cluster.get('Status'),
                        'Engine': cluster.get('Engine'),
                        'EngineVersion': cluster.get('EngineVersion'),
                        'DBClusterMembers': cluster.get('DBClusterMembers', []),
                        'VpcSecurityGroups': cluster.get('VpcSecurityGroups', []),
                        'DBSubnetGroup': cluster.get('DBSubnetGroup'),
                        'Endpoint': cluster.get('Endpoint'),
                        'ReaderEndpoint': cluster.get('ReaderEndpoint'),
                        'MultiAZ': cluster.get('MultiAZ'),
                        'StorageEncrypted': cluster.get('StorageEncrypted'),
                    }
                    clusters.append(cluster_info)

        except Exception as e:
            logger.error(f"获取DocumentDB集群信息失败: {str(e)}")

        return clusters

    def get_memorydb_clusters(self) -> List[Dict[str, Any]]:
        """
        获取MemoryDB集群信息

        Returns:
            List[Dict[str, Any]]: MemoryDB集群列表
        """
        logger.info("获取MemoryDB集群信息")
        clusters = []

        try:
            # 获取所有MemoryDB集群
            response = self.memorydb_client.describe_clusters()

            for cluster in response.get('Clusters', []):
                cluster_info = {
                    'Name': cluster.get('Name'),
                    'Status': cluster.get('Status'),
                    'NodeType': cluster.get('NodeType'),
                    'EngineVersion': cluster.get('EngineVersion'),
                    'ParameterGroupName': cluster.get('ParameterGroupName'),
                    'SubnetGroupName': cluster.get('SubnetGroupName'),
                    'TLSEnabled': cluster.get('TLSEnabled'),
                    'ClusterEndpoint': cluster.get('ClusterEndpoint'),
                    'NodeCount': len(cluster.get('Shards', [])),
                }
                clusters.append(cluster_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.memorydb_client.describe_clusters(
                    NextToken=response['NextToken']
                )

                for cluster in response.get('Clusters', []):
                    cluster_info = {
                        'Name': cluster.get('Name'),
                        'Status': cluster.get('Status'),
                        'NodeType': cluster.get('NodeType'),
                        'EngineVersion': cluster.get('EngineVersion'),
                        'ParameterGroupName': cluster.get('ParameterGroupName'),
                        'SubnetGroupName': cluster.get('SubnetGroupName'),
                        'TLSEnabled': cluster.get('TLSEnabled'),
                        'ClusterEndpoint': cluster.get('ClusterEndpoint'),
                        'NodeCount': len(cluster.get('Shards', [])),
                    }
                    clusters.append(cluster_info)

        except Exception as e:
            logger.error(f"获取MemoryDB集群信息失败: {str(e)}")

        return clusters

    def get_neptune_clusters(self) -> List[Dict[str, Any]]:
        """
        获取Neptune集群信息

        Returns:
            List[Dict[str, Any]]: Neptune集群列表
        """
        logger.info("获取Neptune集群信息")
        clusters = []

        try:
            # 获取所有Neptune集群
            response = self.neptune_client.describe_db_clusters(
                Filters=[{'Name': 'engine', 'Values': ['neptune']}]
            )

            for cluster in response.get('DBClusters', []):
                cluster_info = {
                    'DBClusterIdentifier': cluster.get('DBClusterIdentifier'),
                    'Status': cluster.get('Status'),
                    'Engine': cluster.get('Engine'),
                    'EngineVersion': cluster.get('EngineVersion'),
                    'DBClusterMembers': cluster.get('DBClusterMembers', []),
                    'VpcSecurityGroups': cluster.get('VpcSecurityGroups', []),
                    'DBSubnetGroup': cluster.get('DBSubnetGroup'),
                    'Endpoint': cluster.get('Endpoint'),
                    'ReaderEndpoint': cluster.get('ReaderEndpoint'),
                    'MultiAZ': cluster.get('MultiAZ'),
                    'StorageEncrypted': cluster.get('StorageEncrypted'),
                }
                clusters.append(cluster_info)

            # 处理分页
            while 'Marker' in response:
                response = self.neptune_client.describe_db_clusters(
                    Marker=response['Marker'],
                    Filters=[{'Name': 'engine', 'Values': ['neptune']}]
                )

                for cluster in response.get('DBClusters', []):
                    cluster_info = {
                        'DBClusterIdentifier': cluster.get('DBClusterIdentifier'),
                        'Status': cluster.get('Status'),
                        'Engine': cluster.get('Engine'),
                        'EngineVersion': cluster.get('EngineVersion'),
                        'DBClusterMembers': cluster.get('DBClusterMembers', []),
                        'VpcSecurityGroups': cluster.get('VpcSecurityGroups', []),
                        'DBSubnetGroup': cluster.get('DBSubnetGroup'),
                        'Endpoint': cluster.get('Endpoint'),
                        'ReaderEndpoint': cluster.get('ReaderEndpoint'),
                        'MultiAZ': cluster.get('MultiAZ'),
                        'StorageEncrypted': cluster.get('StorageEncrypted'),
                    }
                    clusters.append(cluster_info)

        except Exception as e:
            logger.error(f"获取Neptune集群信息失败: {str(e)}")

        return clusters

    def get_timestream_databases(self) -> List[Dict[str, Any]]:
        """
        获取Timestream数据库信息

        Returns:
            List[Dict[str, Any]]: Timestream数据库列表
        """
        logger.info("获取Timestream数据库信息")
        databases = []

        try:
            # 获取所有Timestream数据库
            response = self.timestream_client.list_databases()

            for db in response.get('Databases', []):
                db_info = {
                    'DatabaseName': db.get('DatabaseName'),
                    'TableCount': db.get('TableCount'),
                    'KmsKeyId': db.get('KmsKeyId'),
                    'CreationTime': db.get('CreationTime'),
                    'LastUpdatedTime': db.get('LastUpdatedTime'),
                }
                databases.append(db_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.timestream_client.list_databases(
                    NextToken=response['NextToken']
                )

                for db in response.get('Databases', []):
                    db_info = {
                        'DatabaseName': db.get('DatabaseName'),
                        'TableCount': db.get('TableCount'),
                        'KmsKeyId': db.get('KmsKeyId'),
                        'CreationTime': db.get('CreationTime'),
                        'LastUpdatedTime': db.get('LastUpdatedTime'),
                    }
                    databases.append(db_info)

        except Exception as e:
            logger.error(f"获取Timestream数据库信息失败: {str(e)}")

        return databases

    def get_keyspaces(self) -> List[Dict[str, Any]]:
        """
        获取Keyspaces信息

        Returns:
            List[Dict[str, Any]]: Keyspaces列表
        """
        logger.info("获取Keyspaces信息")
        keyspaces = []

        try:
            # 获取所有Keyspaces
            response = self.keyspaces_client.list_keyspaces()

            for keyspace in response.get('keyspaces', []):
                keyspace_info = {
                    'keyspaceName': keyspace.get('keyspaceName'),
                    'resourceArn': keyspace.get('resourceArn'),
                    'replicationStrategy': keyspace.get('replicationStrategy'),
                }
                keyspaces.append(keyspace_info)

            # 处理分页
            while 'nextToken' in response:
                response = self.keyspaces_client.list_keyspaces(
                    nextToken=response['nextToken']
                )

                for keyspace in response.get('keyspaces', []):
                    keyspace_info = {
                        'keyspaceName': keyspace.get('keyspaceName'),
                        'resourceArn': keyspace.get('resourceArn'),
                        'replicationStrategy': keyspace.get('replicationStrategy'),
                    }
                    keyspaces.append(keyspace_info)

        except Exception as e:
            logger.error(f"获取Keyspaces信息失败: {str(e)}")

        return keyspaces

    def get_opensearch_domains(self) -> List[Dict[str, Any]]:
        """
        获取OpenSearch(原ElasticSearch)域信息

        Returns:
            List[Dict[str, Any]]: OpenSearch域列表
        """
        logger.info("获取OpenSearch域信息")
        domains = []

        try:
            # 获取所有OpenSearch域
            response = self.opensearch_client.list_domain_names()
            
            domain_names = [domain['DomainName'] for domain in response.get('DomainNames', [])]
            
            if domain_names:
                # 批量获取域详情
                domains_info = self.opensearch_client.describe_domains(
                    DomainNames=domain_names
                )
                
                for domain in domains_info.get('DomainStatusList', []):
                    domain_info = {
                        'DomainName': domain.get('DomainName'),
                        'DomainId': domain.get('DomainId'),
                        'ARN': domain.get('ARN'),
                        'Created': domain.get('Created'),
                        'Deleted': domain.get('Deleted'),
                        'Endpoint': domain.get('Endpoint'),
                        'EngineVersion': domain.get('EngineVersion'),
                        'Processing': domain.get('Processing'),
                        'UpgradeProcessing': domain.get('UpgradeProcessing'),
                        'ElasticsearchVersion': domain.get('ElasticsearchVersion'),
                        'ElasticsearchClusterConfig': domain.get('ElasticsearchClusterConfig'),
                        'EBSOptions': domain.get('EBSOptions'),
                        'AccessPolicies': domain.get('AccessPolicies'),
                        'SnapshotOptions': domain.get('SnapshotOptions'),
                        'VPCOptions': domain.get('VPCOptions'),
                        'CognitoOptions': domain.get('CognitoOptions'),
                        'EncryptionAtRestOptions': domain.get('EncryptionAtRestOptions'),
                        'NodeToNodeEncryptionOptions': domain.get('NodeToNodeEncryptionOptions'),
                        'AdvancedOptions': domain.get('AdvancedOptions'),
                        'LogPublishingOptions': domain.get('LogPublishingOptions'),
                        'ServiceSoftwareOptions': domain.get('ServiceSoftwareOptions'),
                        'DomainEndpointOptions': domain.get('DomainEndpointOptions'),
                        'AdvancedSecurityOptions': domain.get('AdvancedSecurityOptions'),
                        'AutoTuneOptions': domain.get('AutoTuneOptions'),
                    }
                    domains.append(domain_info)

        except Exception as e:
            logger.error(f"获取OpenSearch域信息失败: {str(e)}")

        return domains

    def get_elasticache_clusters(self) -> List[Dict[str, Any]]:
        """
        获取ElastiCache集群信息

        Returns:
            List[Dict[str, Any]]: ElastiCache集群列表
        """
        logger.info("获取ElastiCache集群信息")
        clusters = []

        try:
            # 获取所有ElastiCache集群
            response = self.elasticache_client.describe_cache_clusters()

            for cluster in response.get('CacheClusters', []):
                cluster_info = {
                    'CacheClusterId': cluster.get('CacheClusterId'),
                    'ConfigurationEndpoint': cluster.get('ConfigurationEndpoint'),
                    'ClientDownloadLandingPage': cluster.get('ClientDownloadLandingPage'),
                    'CacheNodeType': cluster.get('CacheNodeType'),
                    'Engine': cluster.get('Engine'),
                    'EngineVersion': cluster.get('EngineVersion'),
                    'CacheClusterStatus': cluster.get('CacheClusterStatus'),
                    'NumCacheNodes': cluster.get('NumCacheNodes'),
                    'PreferredAvailabilityZone': cluster.get('PreferredAvailabilityZone'),
                    'CacheClusterCreateTime': cluster.get('CacheClusterCreateTime'),
                    'PreferredMaintenanceWindow': cluster.get('PreferredMaintenanceWindow'),
                    'PendingModifiedValues': cluster.get('PendingModifiedValues'),
                    'NotificationConfiguration': cluster.get('NotificationConfiguration'),
                    'CacheSecurityGroups': cluster.get('CacheSecurityGroups'),
                    'CacheParameterGroup': cluster.get('CacheParameterGroup'),
                    'CacheSubnetGroupName': cluster.get('CacheSubnetGroupName'),
                    'AutoMinorVersionUpgrade': cluster.get('AutoMinorVersionUpgrade'),
                    'SecurityGroups': cluster.get('SecurityGroups'),
                    'ReplicationGroupId': cluster.get('ReplicationGroupId'),
                    'SnapshotRetentionLimit': cluster.get('SnapshotRetentionLimit'),
                    'SnapshotWindow': cluster.get('SnapshotWindow'),
                    'AuthTokenEnabled': cluster.get('AuthTokenEnabled'),
                    'TransitEncryptionEnabled': cluster.get('TransitEncryptionEnabled'),
                    'AtRestEncryptionEnabled': cluster.get('AtRestEncryptionEnabled'),
                }
                clusters.append(cluster_info)

            # 处理分页
            while 'Marker' in response:
                response = self.elasticache_client.describe_cache_clusters(
                    Marker=response['Marker']
                )

                for cluster in response.get('CacheClusters', []):
                    cluster_info = {
                        'CacheClusterId': cluster.get('CacheClusterId'),
                        'ConfigurationEndpoint': cluster.get('ConfigurationEndpoint'),
                        'ClientDownloadLandingPage': cluster.get('ClientDownloadLandingPage'),
                        'CacheNodeType': cluster.get('CacheNodeType'),
                        'Engine': cluster.get('Engine'),
                        'EngineVersion': cluster.get('EngineVersion'),
                        'CacheClusterStatus': cluster.get('CacheClusterStatus'),
                        'NumCacheNodes': cluster.get('NumCacheNodes'),
                        'PreferredAvailabilityZone': cluster.get('PreferredAvailabilityZone'),
                        'CacheClusterCreateTime': cluster.get('CacheClusterCreateTime'),
                        'PreferredMaintenanceWindow': cluster.get('PreferredMaintenanceWindow'),
                        'PendingModifiedValues': cluster.get('PendingModifiedValues'),
                        'NotificationConfiguration': cluster.get('NotificationConfiguration'),
                        'CacheSecurityGroups': cluster.get('CacheSecurityGroups'),
                        'CacheParameterGroup': cluster.get('CacheParameterGroup'),
                        'CacheSubnetGroupName': cluster.get('CacheSubnetGroupName'),
                        'AutoMinorVersionUpgrade': cluster.get('AutoMinorVersionUpgrade'),
                        'SecurityGroups': cluster.get('SecurityGroups'),
                        'ReplicationGroupId': cluster.get('ReplicationGroupId'),
                        'SnapshotRetentionLimit': cluster.get('SnapshotRetentionLimit'),
                        'SnapshotWindow': cluster.get('SnapshotWindow'),
                        'AuthTokenEnabled': cluster.get('AuthTokenEnabled'),
                        'TransitEncryptionEnabled': cluster.get('TransitEncryptionEnabled'),
                        'AtRestEncryptionEnabled': cluster.get('AtRestEncryptionEnabled'),
                    }
                    clusters.append(cluster_info)

        except Exception as e:
            logger.error(f"获取ElastiCache集群信息失败: {str(e)}")

        return clusters

    def get_elasticache_replication_groups(self) -> List[Dict[str, Any]]:
        """
        获取ElastiCache复制组信息（Redis集群模式）

        Returns:
            List[Dict[str, Any]]: ElastiCache复制组列表
        """
        logger.info("获取ElastiCache复制组信息")
        replication_groups = []

        try:
            # 获取所有ElastiCache复制组
            response = self.elasticache_client.describe_replication_groups()

            for group in response.get('ReplicationGroups', []):
                group_info = {
                    'ReplicationGroupId': group.get('ReplicationGroupId'),
                    'Description': group.get('Description'),
                    'Status': group.get('Status'),
                    'PendingModifiedValues': group.get('PendingModifiedValues'),
                    'MemberClusters': group.get('MemberClusters'),
                    'NodeGroups': group.get('NodeGroups'),
                    'SnapshottingClusterId': group.get('SnapshottingClusterId'),
                    'AutomaticFailover': group.get('AutomaticFailover'),
                    'MultiAZ': group.get('MultiAZ'),
                    'ConfigurationEndpoint': group.get('ConfigurationEndpoint'),
                    'SnapshotRetentionLimit': group.get('SnapshotRetentionLimit'),
                    'SnapshotWindow': group.get('SnapshotWindow'),
                    'ClusterEnabled': group.get('ClusterEnabled'),
                    'CacheNodeType': group.get('CacheNodeType'),
                    'AuthTokenEnabled': group.get('AuthTokenEnabled'),
                    'TransitEncryptionEnabled': group.get('TransitEncryptionEnabled'),
                    'AtRestEncryptionEnabled': group.get('AtRestEncryptionEnabled'),
                    'KmsKeyId': group.get('KmsKeyId'),
                }
                replication_groups.append(group_info)

            # 处理分页
            while 'Marker' in response:
                response = self.elasticache_client.describe_replication_groups(
                    Marker=response['Marker']
                )

                for group in response.get('ReplicationGroups', []):
                    group_info = {
                        'ReplicationGroupId': group.get('ReplicationGroupId'),
                        'Description': group.get('Description'),
                        'Status': group.get('Status'),
                        'PendingModifiedValues': group.get('PendingModifiedValues'),
                        'MemberClusters': group.get('MemberClusters'),
                        'NodeGroups': group.get('NodeGroups'),
                        'SnapshottingClusterId': group.get('SnapshottingClusterId'),
                        'AutomaticFailover': group.get('AutomaticFailover'),
                        'MultiAZ': group.get('MultiAZ'),
                        'ConfigurationEndpoint': group.get('ConfigurationEndpoint'),
                        'SnapshotRetentionLimit': group.get('SnapshotRetentionLimit'),
                        'SnapshotWindow': group.get('SnapshotWindow'),
                        'ClusterEnabled': group.get('ClusterEnabled'),
                        'CacheNodeType': group.get('CacheNodeType'),
                        'AuthTokenEnabled': group.get('AuthTokenEnabled'),
                        'TransitEncryptionEnabled': group.get('TransitEncryptionEnabled'),
                        'AtRestEncryptionEnabled': group.get('AtRestEncryptionEnabled'),
                        'KmsKeyId': group.get('KmsKeyId'),
                    }
                    replication_groups.append(group_info)

        except Exception as e:
            logger.error(f"获取ElastiCache复制组信息失败: {str(e)}")

        return replication_groups

    def get_all_database_assets(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        获取所有数据库资源，按类型分开并返回单个资源项

        Returns:
            Dict[str, Dict[str, Dict[str, Any]]]: 按类型分开的数据库资源，每个资源项单独存储
        """
        # RDS实例（包括Oracle等引擎）
        rds_instances = {instance['DBInstanceIdentifier']: instance for instance in self.get_rds_instances()}
        
        # DynamoDB表
        dynamodb_tables = {table.get('TableName', ''): table for table in self.get_dynamodb_tables()}
        
        # DocumentDB集群
        docdb_clusters = {cluster['DBClusterIdentifier']: cluster for cluster in self.get_documentdb_clusters()}
        
        # MemoryDB集群
        memorydb_clusters = {cluster['Name']: cluster for cluster in self.get_memorydb_clusters()}
        
        # Neptune集群
        neptune_clusters = {cluster['DBClusterIdentifier']: cluster for cluster in self.get_neptune_clusters()}
        
        # Timestream数据库
        timestream_dbs = {db['DatabaseName']: db for db in self.get_timestream_databases()}
        
        # Keyspaces
        keyspaces = {ks['keyspaceName']: ks for ks in self.get_keyspaces()}
        
        # OpenSearch(原ElasticSearch)域
        opensearch_domains = {domain['DomainName']: domain for domain in self.get_opensearch_domains()}
        
        # ElastiCache集群
        elasticache_clusters = {cluster['CacheClusterId']: cluster for cluster in self.get_elasticache_clusters()}
        
        # ElastiCache复制组（Redis集群模式）
        elasticache_replication_groups = {group['ReplicationGroupId']: group for group in self.get_elasticache_replication_groups()}
        
        return {
            'rds': rds_instances,
            'dynamodb': dynamodb_tables,
            'documentdb': docdb_clusters,
            'memorydb': memorydb_clusters,
            'neptune': neptune_clusters,
            'timestream': timestream_dbs,
            'keyspaces': keyspaces,
            'opensearch': opensearch_domains,
            'elasticache_clusters': elasticache_clusters,
            'elasticache_replication_groups': elasticache_replication_groups
        } 