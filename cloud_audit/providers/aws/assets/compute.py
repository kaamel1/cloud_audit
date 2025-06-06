"""
AWS计算资源处理模块，负责获取EC2实例、Lambda函数等计算资源信息。
"""
import boto3
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class ComputeAssetCollector:
    """AWS计算资源收集器"""

    def __init__(self, session):
        """
        初始化计算资源收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        self.ec2_client = session.get_client('ec2')
        self.lambda_client = session.get_client('lambda')
        self.elb_client = session.get_client('elbv2')  # 用于ALB和NLB

    def get_ec2_instances(self) -> List[Dict[str, Any]]:
        """
        获取EC2实例信息

        Returns:
            List[Dict[str, Any]]: EC2实例列表
        """
        logger.info("获取EC2实例信息")
        instances = []

        try:
            # 获取所有EC2实例
            response = self.ec2_client.describe_instances()

            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_info = {
                        'InstanceId': instance.get('InstanceId'),
                        'InstanceType': instance.get('InstanceType'),
                        'State': instance.get('State', {}).get('Name'),
                        'PrivateIpAddress': instance.get('PrivateIpAddress'),
                        'PublicIpAddress': instance.get('PublicIpAddress'),
                        'LaunchTime': instance.get('LaunchTime'),
                        'VpcId': instance.get('VpcId'),
                        'SubnetId': instance.get('SubnetId'),
                        'Tags': instance.get('Tags', []),
                        'SecurityGroups': instance.get('SecurityGroups', []),
                        'IamInstanceProfile': instance.get('IamInstanceProfile'),
                    }
                    instances.append(instance_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_instances(
                    NextToken=response['NextToken']
                )

                for reservation in response.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instance_info = {
                            'InstanceId': instance.get('InstanceId'),
                            'InstanceType': instance.get('InstanceType'),
                            'State': instance.get('State', {}).get('Name'),
                            'PrivateIpAddress': instance.get('PrivateIpAddress'),
                            'PublicIpAddress': instance.get('PublicIpAddress'),
                            'LaunchTime': instance.get('LaunchTime'),
                            'VpcId': instance.get('VpcId'),
                            'SubnetId': instance.get('SubnetId'),
                            'Tags': instance.get('Tags', []),
                            'SecurityGroups': instance.get('SecurityGroups', []),
                            'IamInstanceProfile': instance.get('IamInstanceProfile'),
                        }
                        instances.append(instance_info)

        except Exception as e:
            logger.error(f"获取EC2实例信息失败: {str(e)}")

        return instances

    def get_lambda_functions(self) -> List[Dict[str, Any]]:
        """
        获取Lambda函数信息

        Returns:
            List[Dict[str, Any]]: Lambda函数列表
        """
        logger.info("获取Lambda函数信息")
        functions = []

        try:
            # 获取所有Lambda函数
            response = self.lambda_client.list_functions()

            for function in response.get('Functions', []):
                function_info = {
                    'FunctionName': function.get('FunctionName'),
                    'FunctionArn': function.get('FunctionArn'),
                    'Runtime': function.get('Runtime'),
                    'Role': function.get('Role'),
                    'Handler': function.get('Handler'),
                    'CodeSize': function.get('CodeSize'),
                    'Description': function.get('Description'),
                    'Timeout': function.get('Timeout'),
                    'MemorySize': function.get('MemorySize'),
                    'LastModified': function.get('LastModified'),
                    'VpcConfig': function.get('VpcConfig'),
                }
                functions.append(function_info)

            # 处理分页
            while 'NextMarker' in response:
                response = self.lambda_client.list_functions(
                    Marker=response['NextMarker']
                )

                for function in response.get('Functions', []):
                    function_info = {
                        'FunctionName': function.get('FunctionName'),
                        'FunctionArn': function.get('FunctionArn'),
                        'Runtime': function.get('Runtime'),
                        'Role': function.get('Role'),
                        'Handler': function.get('Handler'),
                        'CodeSize': function.get('CodeSize'),
                        'Description': function.get('Description'),
                        'Timeout': function.get('Timeout'),
                        'MemorySize': function.get('MemorySize'),
                        'LastModified': function.get('LastModified'),
                        'VpcConfig': function.get('VpcConfig'),
                    }
                    functions.append(function_info)

        except Exception as e:
            logger.error(f"获取Lambda函数信息失败: {str(e)}")

        return functions

    def get_load_balancers(self) -> List[Dict[str, Any]]:
        """
        获取负载均衡器信息（ALB、NLB）

        Returns:
            List[Dict[str, Any]]: 负载均衡器列表
        """
        logger.info("获取负载均衡器信息")
        load_balancers = []

        try:
            # 获取所有负载均衡器
            response = self.elb_client.describe_load_balancers()

            for lb in response.get('LoadBalancers', []):
                # 获取负载均衡器的标签
                tags_response = self.elb_client.describe_tags(
                    ResourceArns=[lb.get('LoadBalancerArn')]
                )
                tags = tags_response.get('TagDescriptions', [{}])[0].get('Tags', [])

                # 获取负载均衡器的监听器
                listeners_response = self.elb_client.describe_listeners(
                    LoadBalancerArn=lb.get('LoadBalancerArn')
                )
                listeners = listeners_response.get('Listeners', [])

                # 获取负载均衡器的目标组
                target_groups = []
                try:
                    tg_response = self.elb_client.describe_target_groups(
                        LoadBalancerArn=lb.get('LoadBalancerArn')
                    )
                    for tg in tg_response.get('TargetGroups', []):
                        # 获取目标组的目标健康状态
                        targets_health = []
                        try:
                            health_response = self.elb_client.describe_target_health(
                                TargetGroupArn=tg.get('TargetGroupArn')
                            )
                            targets_health = health_response.get('TargetHealthDescriptions', [])
                        except Exception as e:
                            logger.error(f"获取目标组 {tg.get('TargetGroupArn')} 的目标健康状态失败: {str(e)}")

                        tg_info = {
                            'TargetGroupArn': tg.get('TargetGroupArn'),
                            'TargetGroupName': tg.get('TargetGroupName'),
                            'Protocol': tg.get('Protocol'),
                            'Port': tg.get('Port'),
                            'VpcId': tg.get('VpcId'),
                            'HealthCheckProtocol': tg.get('HealthCheckProtocol'),
                            'HealthCheckPort': tg.get('HealthCheckPort'),
                            'HealthCheckPath': tg.get('HealthCheckPath'),
                            'HealthCheckIntervalSeconds': tg.get('HealthCheckIntervalSeconds'),
                            'HealthCheckTimeoutSeconds': tg.get('HealthCheckTimeoutSeconds'),
                            'HealthyThresholdCount': tg.get('HealthyThresholdCount'),
                            'UnhealthyThresholdCount': tg.get('UnhealthyThresholdCount'),
                            'TargetType': tg.get('TargetType'),
                            'Targets': targets_health
                        }
                        target_groups.append(tg_info)
                except Exception as e:
                    logger.error(f"获取负载均衡器 {lb.get('LoadBalancerArn')} 的目标组失败: {str(e)}")

                lb_info = {
                    'LoadBalancerArn': lb.get('LoadBalancerArn'),
                    'DNSName': lb.get('DNSName'),
                    'LoadBalancerName': lb.get('LoadBalancerName'),
                    'Type': lb.get('Type'),  # 'application' 表示 ALB, 'network' 表示 NLB
                    'Scheme': lb.get('Scheme'),
                    'VpcId': lb.get('VpcId'),
                    'State': lb.get('State'),
                    'AvailabilityZones': lb.get('AvailabilityZones', []),
                    'SecurityGroups': lb.get('SecurityGroups', []),
                    'IpAddressType': lb.get('IpAddressType'),
                    'CreatedTime': lb.get('CreatedTime'),
                    'Tags': tags,
                    'Listeners': listeners,
                    'TargetGroups': target_groups
                }
                load_balancers.append(lb_info)

            # 处理分页
            while 'NextMarker' in response:
                response = self.elb_client.describe_load_balancers(
                    Marker=response['NextMarker']
                )

                for lb in response.get('LoadBalancers', []):
                    # 获取负载均衡器的标签
                    tags_response = self.elb_client.describe_tags(
                        ResourceArns=[lb.get('LoadBalancerArn')]
                    )
                    tags = tags_response.get('TagDescriptions', [{}])[0].get('Tags', [])

                    # 获取负载均衡器的监听器
                    listeners_response = self.elb_client.describe_listeners(
                        LoadBalancerArn=lb.get('LoadBalancerArn')
                    )
                    listeners = listeners_response.get('Listeners', [])

                    # 获取负载均衡器的目标组
                    target_groups = []
                    try:
                        tg_response = self.elb_client.describe_target_groups(
                            LoadBalancerArn=lb.get('LoadBalancerArn')
                        )
                        for tg in tg_response.get('TargetGroups', []):
                            # 获取目标组的目标健康状态
                            targets_health = []
                            try:
                                health_response = self.elb_client.describe_target_health(
                                    TargetGroupArn=tg.get('TargetGroupArn')
                                )
                                targets_health = health_response.get('TargetHealthDescriptions', [])
                            except Exception as e:
                                logger.error(f"获取目标组 {tg.get('TargetGroupArn')} 的目标健康状态失败: {str(e)}")

                            tg_info = {
                                'TargetGroupArn': tg.get('TargetGroupArn'),
                                'TargetGroupName': tg.get('TargetGroupName'),
                                'Protocol': tg.get('Protocol'),
                                'Port': tg.get('Port'),
                                'VpcId': tg.get('VpcId'),
                                'HealthCheckProtocol': tg.get('HealthCheckProtocol'),
                                'HealthCheckPort': tg.get('HealthCheckPort'),
                                'HealthCheckPath': tg.get('HealthCheckPath'),
                                'HealthCheckIntervalSeconds': tg.get('HealthCheckIntervalSeconds'),
                                'HealthCheckTimeoutSeconds': tg.get('HealthCheckTimeoutSeconds'),
                                'HealthyThresholdCount': tg.get('HealthyThresholdCount'),
                                'UnhealthyThresholdCount': tg.get('UnhealthyThresholdCount'),
                                'TargetType': tg.get('TargetType'),
                                'Targets': targets_health
                            }
                            target_groups.append(tg_info)
                    except Exception as e:
                        logger.error(f"获取负载均衡器 {lb.get('LoadBalancerArn')} 的目标组失败: {str(e)}")

                    lb_info = {
                        'LoadBalancerArn': lb.get('LoadBalancerArn'),
                        'DNSName': lb.get('DNSName'),
                        'LoadBalancerName': lb.get('LoadBalancerName'),
                        'Type': lb.get('Type'),  # 'application' 表示 ALB, 'network' 表示 NLB
                        'Scheme': lb.get('Scheme'),
                        'VpcId': lb.get('VpcId'),
                        'State': lb.get('State'),
                        'AvailabilityZones': lb.get('AvailabilityZones', []),
                        'SecurityGroups': lb.get('SecurityGroups', []),
                        'IpAddressType': lb.get('IpAddressType'),
                        'CreatedTime': lb.get('CreatedTime'),
                        'Tags': tags,
                        'Listeners': listeners,
                        'TargetGroups': target_groups
                    }
                    load_balancers.append(lb_info)

        except Exception as e:
            logger.error(f"获取负载均衡器信息失败: {str(e)}")

        return load_balancers

    def get_classic_load_balancers(self) -> List[Dict[str, Any]]:
        """
        获取经典负载均衡器信息（Classic ELB）

        Returns:
            List[Dict[str, Any]]: 经典负载均衡器列表
        """
        logger.info("获取经典负载均衡器信息")
        classic_lbs = []

        try:
            # 创建经典ELB客户端
            elb_classic_client = self.session.get_client('elb')
            
            # 获取所有经典负载均衡器
            response = elb_classic_client.describe_load_balancers()

            for lb in response.get('LoadBalancerDescriptions', []):
                # 获取经典负载均衡器的标签
                tags_response = elb_classic_client.describe_tags(
                    LoadBalancerNames=[lb.get('LoadBalancerName')]
                )
                tags = tags_response.get('TagDescriptions', [{}])[0].get('Tags', [])

                lb_info = {
                    'LoadBalancerName': lb.get('LoadBalancerName'),
                    'DNSName': lb.get('DNSName'),
                    'CanonicalHostedZoneName': lb.get('CanonicalHostedZoneName'),
                    'CanonicalHostedZoneNameID': lb.get('CanonicalHostedZoneNameID'),
                    'ListenerDescriptions': lb.get('ListenerDescriptions', []),
                    'Policies': lb.get('Policies', {}),
                    'BackendServerDescriptions': lb.get('BackendServerDescriptions', []),
                    'AvailabilityZones': lb.get('AvailabilityZones', []),
                    'Subnets': lb.get('Subnets', []),
                    'VPCId': lb.get('VPCId'),
                    'Instances': lb.get('Instances', []),
                    'HealthCheck': lb.get('HealthCheck', {}),
                    'SourceSecurityGroup': lb.get('SourceSecurityGroup', {}),
                    'SecurityGroups': lb.get('SecurityGroups', []),
                    'CreatedTime': lb.get('CreatedTime'),
                    'Scheme': lb.get('Scheme'),
                    'Tags': tags
                }
                classic_lbs.append(lb_info)

            # 处理分页
            while 'NextMarker' in response:
                response = elb_classic_client.describe_load_balancers(
                    Marker=response['NextMarker']
                )

                for lb in response.get('LoadBalancerDescriptions', []):
                    # 获取经典负载均衡器的标签
                    tags_response = elb_classic_client.describe_tags(
                        LoadBalancerNames=[lb.get('LoadBalancerName')]
                    )
                    tags = tags_response.get('TagDescriptions', [{}])[0].get('Tags', [])

                    lb_info = {
                        'LoadBalancerName': lb.get('LoadBalancerName'),
                        'DNSName': lb.get('DNSName'),
                        'CanonicalHostedZoneName': lb.get('CanonicalHostedZoneName'),
                        'CanonicalHostedZoneNameID': lb.get('CanonicalHostedZoneNameID'),
                        'ListenerDescriptions': lb.get('ListenerDescriptions', []),
                        'Policies': lb.get('Policies', {}),
                        'BackendServerDescriptions': lb.get('BackendServerDescriptions', []),
                        'AvailabilityZones': lb.get('AvailabilityZones', []),
                        'Subnets': lb.get('Subnets', []),
                        'VPCId': lb.get('VPCId'),
                        'Instances': lb.get('Instances', []),
                        'HealthCheck': lb.get('HealthCheck', {}),
                        'SourceSecurityGroup': lb.get('SourceSecurityGroup', {}),
                        'SecurityGroups': lb.get('SecurityGroups', []),
                        'CreatedTime': lb.get('CreatedTime'),
                        'Scheme': lb.get('Scheme'),
                        'Tags': tags
                    }
                    classic_lbs.append(lb_info)

        except Exception as e:
            logger.error(f"获取经典负载均衡器信息失败: {str(e)}")

        return classic_lbs

    def get_ecs_clusters(self) -> List[Dict[str, Any]]:
        """
        获取ECS集群信息

        Returns:
            List[Dict[str, Any]]: ECS集群列表
        """
        logger.info("获取ECS集群信息")
        clusters = []

        try:
            # 创建ECS客户端
            ecs_client = self.session.get_client('ecs')
            
            # 获取所有ECS集群
            response = ecs_client.list_clusters()

            for cluster_arn in response.get('clusterArns', []):
                # 获取集群详细信息
                cluster_detail_response = ecs_client.describe_clusters(
                    clusters=[cluster_arn],
                    include=['ATTACHMENTS', 'CONFIGURATIONS', 'SETTINGS', 'STATISTICS', 'TAGS']
                )
                
                for cluster in cluster_detail_response.get('clusters', []):
                    cluster_info = {
                        'clusterArn': cluster.get('clusterArn'),
                        'clusterName': cluster.get('clusterName'),
                        'configuration': cluster.get('configuration'),
                        'status': cluster.get('status'),
                        'registeredContainerInstancesCount': cluster.get('registeredContainerInstancesCount'),
                        'runningTasksCount': cluster.get('runningTasksCount'),
                        'pendingTasksCount': cluster.get('pendingTasksCount'),
                        'activeServicesCount': cluster.get('activeServicesCount'),
                        'statistics': cluster.get('statistics', []),
                        'settings': cluster.get('settings', []),
                        'capacityProviders': cluster.get('capacityProviders', []),
                        'defaultCapacityProviderStrategy': cluster.get('defaultCapacityProviderStrategy', []),
                        'attachments': cluster.get('attachments', []),
                        'attachmentsStatus': cluster.get('attachmentsStatus'),
                        'tags': cluster.get('tags', []),
                    }
                    clusters.append(cluster_info)

            # 处理分页
            while 'nextToken' in response:
                response = ecs_client.list_clusters(nextToken=response['nextToken'])
                
                for cluster_arn in response.get('clusterArns', []):
                    cluster_detail_response = ecs_client.describe_clusters(
                        clusters=[cluster_arn],
                        include=['ATTACHMENTS', 'CONFIGURATIONS', 'SETTINGS', 'STATISTICS', 'TAGS']
                    )
                    
                    for cluster in cluster_detail_response.get('clusters', []):
                        cluster_info = {
                            'clusterArn': cluster.get('clusterArn'),
                            'clusterName': cluster.get('clusterName'),
                            'configuration': cluster.get('configuration'),
                            'status': cluster.get('status'),
                            'registeredContainerInstancesCount': cluster.get('registeredContainerInstancesCount'),
                            'runningTasksCount': cluster.get('runningTasksCount'),
                            'pendingTasksCount': cluster.get('pendingTasksCount'),
                            'activeServicesCount': cluster.get('activeServicesCount'),
                            'statistics': cluster.get('statistics', []),
                            'settings': cluster.get('settings', []),
                            'capacityProviders': cluster.get('capacityProviders', []),
                            'defaultCapacityProviderStrategy': cluster.get('defaultCapacityProviderStrategy', []),
                            'attachments': cluster.get('attachments', []),
                            'attachmentsStatus': cluster.get('attachmentsStatus'),
                            'tags': cluster.get('tags', []),
                        }
                        clusters.append(cluster_info)

        except Exception as e:
            logger.error(f"获取ECS集群信息失败: {str(e)}")

        return clusters

    def get_ecs_services(self) -> List[Dict[str, Any]]:
        """
        获取ECS服务信息

        Returns:
            List[Dict[str, Any]]: ECS服务列表
        """
        logger.info("获取ECS服务信息")
        all_services = []

        try:
            # 创建ECS客户端
            ecs_client = self.session.get_client('ecs')
            
            # 首先获取所有集群
            clusters_response = ecs_client.list_clusters()
            
            for cluster_arn in clusters_response.get('clusterArns', []):
                # 获取每个集群的服务
                services_response = ecs_client.list_services(cluster=cluster_arn)
                
                if services_response.get('serviceArns'):
                    # 获取服务详细信息
                    services_detail_response = ecs_client.describe_services(
                        cluster=cluster_arn,
                        services=services_response['serviceArns'],
                        include=['TAGS']
                    )
                    
                    for service in services_detail_response.get('services', []):
                        service_info = {
                            'serviceArn': service.get('serviceArn'),
                            'serviceName': service.get('serviceName'),
                            'clusterArn': service.get('clusterArn'),
                            'loadBalancers': service.get('loadBalancers', []),
                            'serviceRegistries': service.get('serviceRegistries', []),
                            'status': service.get('status'),
                            'taskDefinition': service.get('taskDefinition'),
                            'desiredCount': service.get('desiredCount'),
                            'runningCount': service.get('runningCount'),
                            'pendingCount': service.get('pendingCount'),
                            'launchType': service.get('launchType'),
                            'capacityProviderStrategy': service.get('capacityProviderStrategy', []),
                            'platformVersion': service.get('platformVersion'),
                            'platformFamily': service.get('platformFamily'),
                            'role': service.get('role'),
                            'deploymentConfiguration': service.get('deploymentConfiguration'),
                            'deployments': service.get('deployments', []),
                            'networkConfiguration': service.get('networkConfiguration'),
                            'healthCheckGracePeriodSeconds': service.get('healthCheckGracePeriodSeconds'),
                            'schedulingStrategy': service.get('schedulingStrategy'),
                            'enableExecuteCommand': service.get('enableExecuteCommand'),
                            'enableECSManagedTags': service.get('enableECSManagedTags'),
                            'propagateTags': service.get('propagateTags'),
                            'createdAt': service.get('createdAt'),
                            'createdBy': service.get('createdBy'),
                            'tags': service.get('tags', []),
                        }
                        all_services.append(service_info)
                
                # 处理服务分页
                while 'nextToken' in services_response:
                    services_response = ecs_client.list_services(
                        cluster=cluster_arn,
                        nextToken=services_response['nextToken']
                    )
                    
                    if services_response.get('serviceArns'):
                        services_detail_response = ecs_client.describe_services(
                            cluster=cluster_arn,
                            services=services_response['serviceArns'],
                            include=['TAGS']
                        )
                        
                        for service in services_detail_response.get('services', []):
                            service_info = {
                                'serviceArn': service.get('serviceArn'),
                                'serviceName': service.get('serviceName'),
                                'clusterArn': service.get('clusterArn'),
                                'loadBalancers': service.get('loadBalancers', []),
                                'serviceRegistries': service.get('serviceRegistries', []),
                                'status': service.get('status'),
                                'taskDefinition': service.get('taskDefinition'),
                                'desiredCount': service.get('desiredCount'),
                                'runningCount': service.get('runningCount'),
                                'pendingCount': service.get('pendingCount'),
                                'launchType': service.get('launchType'),
                                'capacityProviderStrategy': service.get('capacityProviderStrategy', []),
                                'platformVersion': service.get('platformVersion'),
                                'platformFamily': service.get('platformFamily'),
                                'role': service.get('role'),
                                'deploymentConfiguration': service.get('deploymentConfiguration'),
                                'deployments': service.get('deployments', []),
                                'networkConfiguration': service.get('networkConfiguration'),
                                'healthCheckGracePeriodSeconds': service.get('healthCheckGracePeriodSeconds'),
                                'schedulingStrategy': service.get('schedulingStrategy'),
                                'enableExecuteCommand': service.get('enableExecuteCommand'),
                                'enableECSManagedTags': service.get('enableECSManagedTags'),
                                'propagateTags': service.get('propagateTags'),
                                'createdAt': service.get('createdAt'),
                                'createdBy': service.get('createdBy'),
                                'tags': service.get('tags', []),
                            }
                            all_services.append(service_info)

            # 处理集群分页
            while 'nextToken' in clusters_response:
                clusters_response = ecs_client.list_clusters(nextToken=clusters_response['nextToken'])
                
                for cluster_arn in clusters_response.get('clusterArns', []):
                    services_response = ecs_client.list_services(cluster=cluster_arn)
                    
                    if services_response.get('serviceArns'):
                        services_detail_response = ecs_client.describe_services(
                            cluster=cluster_arn,
                            services=services_response['serviceArns'],
                            include=['TAGS']
                        )
                        
                        for service in services_detail_response.get('services', []):
                            service_info = {
                                'serviceArn': service.get('serviceArn'),
                                'serviceName': service.get('serviceName'),
                                'clusterArn': service.get('clusterArn'),
                                'loadBalancers': service.get('loadBalancers', []),
                                'serviceRegistries': service.get('serviceRegistries', []),
                                'status': service.get('status'),
                                'taskDefinition': service.get('taskDefinition'),
                                'desiredCount': service.get('desiredCount'),
                                'runningCount': service.get('runningCount'),
                                'pendingCount': service.get('pendingCount'),
                                'launchType': service.get('launchType'),
                                'capacityProviderStrategy': service.get('capacityProviderStrategy', []),
                                'platformVersion': service.get('platformVersion'),
                                'platformFamily': service.get('platformFamily'),
                                'role': service.get('role'),
                                'deploymentConfiguration': service.get('deploymentConfiguration'),
                                'deployments': service.get('deployments', []),
                                'networkConfiguration': service.get('networkConfiguration'),
                                'healthCheckGracePeriodSeconds': service.get('healthCheckGracePeriodSeconds'),
                                'schedulingStrategy': service.get('schedulingStrategy'),
                                'enableExecuteCommand': service.get('enableExecuteCommand'),
                                'enableECSManagedTags': service.get('enableECSManagedTags'),
                                'propagateTags': service.get('propagateTags'),
                                'createdAt': service.get('createdAt'),
                                'createdBy': service.get('createdBy'),
                                'tags': service.get('tags', []),
                            }
                            all_services.append(service_info)

        except Exception as e:
            logger.error(f"获取ECS服务信息失败: {str(e)}")

        return all_services

    def get_all_compute_assets(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        获取所有计算资源，按类型分开并返回单个资源项

        Returns:
            Dict[str, Dict[str, Dict[str, Any]]]: 按类型分开的计算资源，每个资源项单独存储
        """
        ec2_instances = {instance['InstanceId']: instance for instance in self.get_ec2_instances()}
        lambda_functions = {func['FunctionName']: func for func in self.get_lambda_functions()}
        
        # 获取负载均衡器（ALB、NLB）
        load_balancers = {lb['LoadBalancerArn']: lb for lb in self.get_load_balancers()}
        
        # 获取经典负载均衡器（Classic ELB）
        classic_lbs = {lb['LoadBalancerName']: lb for lb in self.get_classic_load_balancers()}
        
        # 获取ECS集群
        ecs_clusters = {cluster['clusterArn']: cluster for cluster in self.get_ecs_clusters()}
        
        # 获取ECS服务
        ecs_services = {service['serviceArn']: service for service in self.get_ecs_services()}
        
        return {
            'ec2': ec2_instances,
            'lambda': lambda_functions,
            'load_balancers': load_balancers,
            'classic_load_balancers': classic_lbs,
            'ecs_clusters': ecs_clusters,
            'ecs_services': ecs_services,
        }
