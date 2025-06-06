"""
AWS VPC流日志和跨账户资源共享处理模块，负责获取VPC流日志、RAM共享资源等信息。
"""
import boto3
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class FlowLogsAndSharingCollector:
    """AWS VPC流日志和资源共享收集器"""

    def __init__(self, session):
        """
        初始化VPC流日志和资源共享收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        self.ec2_client = session.get_client('ec2')
        self.ram_client = session.get_client('ram')
        self.logs_client = session.get_client('logs')
        self.cloudwatch_client = session.get_client('cloudwatch')

    def get_vpc_flow_logs(self) -> List[Dict[str, Any]]:
        """
        获取VPC流日志信息

        Returns:
            List[Dict[str, Any]]: VPC流日志列表
        """
        logger.info("获取VPC流日志信息")
        flow_logs = []

        try:
            # 获取所有VPC流日志
            response = self.ec2_client.describe_flow_logs()

            for log in response.get('FlowLogs', []):
                log_info = {
                    'FlowLogId': log.get('FlowLogId'),
                    'FlowLogStatus': log.get('FlowLogStatus'),
                    'CreationTime': log.get('CreationTime'),
                    'LogGroupName': log.get('LogGroupName'),
                    'TrafficType': log.get('TrafficType'),
                    'ResourceId': log.get('ResourceId'),
                    'ResourceType': log.get('ResourceType'),  # VPC, Subnet, NetworkInterface
                    'LogDestination': log.get('LogDestination'),
                    'LogDestinationType': log.get('LogDestinationType'),  # cloud-watch-logs, s3, kinesis-data-firehose
                    'LogFormat': log.get('LogFormat'),
                    'Tags': log.get('Tags', []),
                    'MaxAggregationInterval': log.get('MaxAggregationInterval'),
                    'DeliverLogsPermissionArn': log.get('DeliverLogsPermissionArn'),
                    'DeliverLogsStatus': log.get('DeliverLogsStatus'),
                    'DeliverLogsErrorMessage': log.get('DeliverLogsErrorMessage'),
                    'DeliverCrossAccountRole': log.get('DeliverCrossAccountRole'),
                }
                flow_logs.append(log_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_flow_logs(
                    NextToken=response['NextToken']
                )

                for log in response.get('FlowLogs', []):
                    log_info = {
                        'FlowLogId': log.get('FlowLogId'),
                        'FlowLogStatus': log.get('FlowLogStatus'),
                        'CreationTime': log.get('CreationTime'),
                        'LogGroupName': log.get('LogGroupName'),
                        'TrafficType': log.get('TrafficType'),
                        'ResourceId': log.get('ResourceId'),
                        'ResourceType': log.get('ResourceType'),
                        'LogDestination': log.get('LogDestination'),
                        'LogDestinationType': log.get('LogDestinationType'),
                        'LogFormat': log.get('LogFormat'),
                        'Tags': log.get('Tags', []),
                        'MaxAggregationInterval': log.get('MaxAggregationInterval'),
                        'DeliverLogsPermissionArn': log.get('DeliverLogsPermissionArn'),
                        'DeliverLogsStatus': log.get('DeliverLogsStatus'),
                        'DeliverLogsErrorMessage': log.get('DeliverLogsErrorMessage'),
                        'DeliverCrossAccountRole': log.get('DeliverCrossAccountRole'),
                    }
                    flow_logs.append(log_info)

        except Exception as e:
            logger.error(f"获取VPC流日志信息失败: {str(e)}")

        return flow_logs

    def get_log_groups_for_flow_logs(self) -> List[Dict[str, Any]]:
        """
        获取流日志相关的CloudWatch日志组信息

        Returns:
            List[Dict[str, Any]]: 流日志相关的日志组列表
        """
        logger.info("获取流日志的CloudWatch日志组信息")
        flow_log_groups = []
        
        try:
            # 获取VPC流日志信息，用于过滤相关的日志组
            flow_logs = self.get_vpc_flow_logs()
            log_group_names = set()
            
            for log in flow_logs:
                if log.get('LogDestinationType') == 'cloud-watch-logs' and log.get('LogGroupName'):
                    log_group_names.add(log.get('LogGroupName'))
            
            # 如果没有流日志使用CloudWatch，则返回空列表
            if not log_group_names:
                return flow_log_groups
                
            # 获取所有日志组
            response = self.logs_client.describe_log_groups()
            
            for group in response.get('logGroups', []):
                if group.get('logGroupName') in log_group_names:
                    log_streams = []
                    
                    # 获取日志组的日志流
                    try:
                        streams_response = self.logs_client.describe_log_streams(
                            logGroupName=group.get('logGroupName')
                        )
                        log_streams = streams_response.get('logStreams', [])
                    except Exception as e:
                        logger.error(f"获取日志组 {group.get('logGroupName')} 的日志流失败: {str(e)}")
                    
                    group_info = {
                        'logGroupName': group.get('logGroupName'),
                        'creationTime': group.get('creationTime'),
                        'retentionInDays': group.get('retentionInDays'),
                        'metricFilterCount': group.get('metricFilterCount'),
                        'arn': group.get('arn'),
                        'storedBytes': group.get('storedBytes'),
                        'kmsKeyId': group.get('kmsKeyId'),
                        'logStreams': log_streams
                    }
                    flow_log_groups.append(group_info)
            
            # 处理分页
            while 'nextToken' in response:
                response = self.logs_client.describe_log_groups(
                    nextToken=response['nextToken']
                )
                
                for group in response.get('logGroups', []):
                    if group.get('logGroupName') in log_group_names:
                        log_streams = []
                        
                        # 获取日志组的日志流
                        try:
                            streams_response = self.logs_client.describe_log_streams(
                                logGroupName=group.get('logGroupName')
                            )
                            log_streams = streams_response.get('logStreams', [])
                        except Exception as e:
                            logger.error(f"获取日志组 {group.get('logGroupName')} 的日志流失败: {str(e)}")
                        
                        group_info = {
                            'logGroupName': group.get('logGroupName'),
                            'creationTime': group.get('creationTime'),
                            'retentionInDays': group.get('retentionInDays'),
                            'metricFilterCount': group.get('metricFilterCount'),
                            'arn': group.get('arn'),
                            'storedBytes': group.get('storedBytes'),
                            'kmsKeyId': group.get('kmsKeyId'),
                            'logStreams': log_streams
                        }
                        flow_log_groups.append(group_info)
                
        except Exception as e:
            logger.error(f"获取流日志相关的CloudWatch日志组信息失败: {str(e)}")
        
        return flow_log_groups

    def get_ram_resource_shares(self) -> List[Dict[str, Any]]:
        """
        获取RAM资源共享信息

        Returns:
            List[Dict[str, Any]]: RAM资源共享列表
        """
        logger.info("获取RAM资源共享信息")
        resource_shares = []

        try:
            # 获取我作为所有者创建的资源共享
            response = self.ram_client.get_resource_shares(
                resourceOwner='SELF'
            )

            for share in response.get('resourceShares', []):
                # 获取资源共享中的资源
                resources = []
                try:
                    resources_response = self.ram_client.list_resources(
                        resourceOwner='SELF',
                        resourceShareArns=[share.get('resourceShareArn')]
                    )
                    resources = resources_response.get('resources', [])
                except Exception as e:
                    logger.error(f"获取资源共享 {share.get('resourceShareArn')} 的资源失败: {str(e)}")

                # 获取资源共享的主体
                principals = []
                try:
                    principals_response = self.ram_client.list_principals(
                        resourceOwner='SELF',
                        resourceShareArns=[share.get('resourceShareArn')]
                    )
                    principals = principals_response.get('principals', [])
                except Exception as e:
                    logger.error(f"获取资源共享 {share.get('resourceShareArn')} 的主体失败: {str(e)}")

                share_info = {
                    'resourceShareArn': share.get('resourceShareArn'),
                    'name': share.get('name'),
                    'owningAccountId': share.get('owningAccountId'),
                    'allowExternalPrincipals': share.get('allowExternalPrincipals'),
                    'status': share.get('status'),
                    'statusMessage': share.get('statusMessage'),
                    'tags': share.get('tags', []),
                    'creationTime': share.get('creationTime'),
                    'lastUpdatedTime': share.get('lastUpdatedTime'),
                    'featureSet': share.get('featureSet'),
                    'resources': resources,
                    'principals': principals
                }
                resource_shares.append(share_info)

            # 处理分页
            while 'nextToken' in response:
                response = self.ram_client.get_resource_shares(
                    resourceOwner='SELF',
                    nextToken=response['nextToken']
                )

                for share in response.get('resourceShares', []):
                    # 获取资源共享中的资源
                    resources = []
                    try:
                        resources_response = self.ram_client.list_resources(
                            resourceOwner='SELF',
                            resourceShareArns=[share.get('resourceShareArn')]
                        )
                        resources = resources_response.get('resources', [])
                    except Exception as e:
                        logger.error(f"获取资源共享 {share.get('resourceShareArn')} 的资源失败: {str(e)}")

                    # 获取资源共享的主体
                    principals = []
                    try:
                        principals_response = self.ram_client.list_principals(
                            resourceOwner='SELF',
                            resourceShareArns=[share.get('resourceShareArn')]
                        )
                        principals = principals_response.get('principals', [])
                    except Exception as e:
                        logger.error(f"获取资源共享 {share.get('resourceShareArn')} 的主体失败: {str(e)}")

                    share_info = {
                        'resourceShareArn': share.get('resourceShareArn'),
                        'name': share.get('name'),
                        'owningAccountId': share.get('owningAccountId'),
                        'allowExternalPrincipals': share.get('allowExternalPrincipals'),
                        'status': share.get('status'),
                        'statusMessage': share.get('statusMessage'),
                        'tags': share.get('tags', []),
                        'creationTime': share.get('creationTime'),
                        'lastUpdatedTime': share.get('lastUpdatedTime'),
                        'featureSet': share.get('featureSet'),
                        'resources': resources,
                        'principals': principals
                    }
                    resource_shares.append(share_info)

            # 获取与我共享的资源
            response = self.ram_client.get_resource_shares(
                resourceOwner='OTHER-ACCOUNTS'
            )

            for share in response.get('resourceShares', []):
                # 获取资源共享中的资源
                resources = []
                try:
                    resources_response = self.ram_client.list_resources(
                        resourceOwner='OTHER-ACCOUNTS',
                        resourceShareArns=[share.get('resourceShareArn')]
                    )
                    resources = resources_response.get('resources', [])
                except Exception as e:
                    logger.error(f"获取资源共享 {share.get('resourceShareArn')} 的资源失败: {str(e)}")

                share_info = {
                    'resourceShareArn': share.get('resourceShareArn'),
                    'name': share.get('name'),
                    'owningAccountId': share.get('owningAccountId'),
                    'allowExternalPrincipals': share.get('allowExternalPrincipals'),
                    'status': share.get('status'),
                    'statusMessage': share.get('statusMessage'),
                    'tags': share.get('tags', []),
                    'creationTime': share.get('creationTime'),
                    'lastUpdatedTime': share.get('lastUpdatedTime'),
                    'featureSet': share.get('featureSet'),
                    'resources': resources,
                    'isSharedWithMe': True
                }
                resource_shares.append(share_info)

            # 处理分页
            while 'nextToken' in response:
                response = self.ram_client.get_resource_shares(
                    resourceOwner='OTHER-ACCOUNTS',
                    nextToken=response['nextToken']
                )

                for share in response.get('resourceShares', []):
                    # 获取资源共享中的资源
                    resources = []
                    try:
                        resources_response = self.ram_client.list_resources(
                            resourceOwner='OTHER-ACCOUNTS',
                            resourceShareArns=[share.get('resourceShareArn')]
                        )
                        resources = resources_response.get('resources', [])
                    except Exception as e:
                        logger.error(f"获取资源共享 {share.get('resourceShareArn')} 的资源失败: {str(e)}")

                    share_info = {
                        'resourceShareArn': share.get('resourceShareArn'),
                        'name': share.get('name'),
                        'owningAccountId': share.get('owningAccountId'),
                        'allowExternalPrincipals': share.get('allowExternalPrincipals'),
                        'status': share.get('status'),
                        'statusMessage': share.get('statusMessage'),
                        'tags': share.get('tags', []),
                        'creationTime': share.get('creationTime'),
                        'lastUpdatedTime': share.get('lastUpdatedTime'),
                        'featureSet': share.get('featureSet'),
                        'resources': resources,
                        'isSharedWithMe': True
                    }
                    resource_shares.append(share_info)

        except Exception as e:
            logger.error(f"获取RAM资源共享信息失败: {str(e)}")

        return resource_shares

    def get_all_flow_logs_and_sharing_assets(self) -> Dict[str, Any]:
        """
        获取所有VPC流日志和资源共享数据

        Returns:
            Dict[str, Any]: 所有VPC流日志和资源共享数据
        """
        flow_logs_and_sharing_assets = {
            'vpc_flow_logs': self.get_vpc_flow_logs(),
            'flow_log_cloudwatch_groups': self.get_log_groups_for_flow_logs(),
            'ram_resource_shares': self.get_ram_resource_shares(),
        }

        return flow_logs_and_sharing_assets 