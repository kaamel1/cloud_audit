"""
AWS Route53全局资源处理模块，负责获取Route53域名、记录集等全局资源信息。
Route53是AWS的全局服务，在不同区域获取到的数据是一致的。
"""
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class DomainRouterGlobalAssetCollector:
    """AWS Route53全局资源收集器"""

    def __init__(self, session):
        """
        初始化Route53全局资源收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        self.route53_client = session.get_client('route53')
        self.route53domains_client = session.get_client('route53domains')

    def get_hosted_zones(self) -> List[Dict[str, Any]]:
        """
        获取Route53托管区域信息

        Returns:
            List[Dict[str, Any]]: 托管区域列表
        """
        logger.info("获取Route53托管区域信息")
        zones = []

        try:
            # 获取所有托管区域
            next_marker = None
            while True:
                if next_marker:
                    response = self.route53_client.list_hosted_zones(Marker=next_marker)
                else:
                    response = self.route53_client.list_hosted_zones()
                
                for zone in response.get('HostedZones', []):
                    zone_info = {
                        'Id': zone.get('Id'),
                        'Name': zone.get('Name'),
                        'CallerReference': zone.get('CallerReference'),
                        'Config': zone.get('Config'),
                        'ResourceRecordSetCount': zone.get('ResourceRecordSetCount'),
                        'LinkedService': zone.get('LinkedService'),
                    }
                    zones.append(zone_info)
                
                if response.get('IsTruncated'):
                    next_marker = response['NextMarker']
                else:
                    break

        except Exception as e:
            logger.error(f"获取Route53托管区域信息失败: {str(e)}")

        return zones

    def get_all_record_sets(self) -> List[Dict[str, Any]]:
        """
        获取所有托管区域的记录集

        Returns:
            List[Dict[str, Any]]: 所有记录集列表
        """
        logger.info("获取所有Route53记录集信息")
        all_record_sets = []

        try:
            # 首先获取所有托管区域
            zones = self.get_hosted_zones()
            
            for zone in zones:
                zone_id = zone['Id']
                record_sets = self.get_record_sets(zone_id)
                
                # 为每个记录集添加zone信息
                for record_set in record_sets:
                    record_set['HostedZoneId'] = zone_id
                    record_set['HostedZoneName'] = zone.get('Name')
                    all_record_sets.append(record_set)

        except Exception as e:
            logger.error(f"获取所有Route53记录集信息失败: {str(e)}")

        return all_record_sets

    def get_record_sets(self, hosted_zone_id: str) -> List[Dict[str, Any]]:
        """
        获取指定托管区域的记录集

        Args:
            hosted_zone_id: 托管区域ID

        Returns:
            List[Dict[str, Any]]: 记录集列表
        """
        logger.info(f"获取托管区域 {hosted_zone_id} 的记录集")
        record_sets = []

        try:
            # 获取指定托管区域的所有记录集
            next_record_name = None
            next_record_type = None
            while True:
                params = {'HostedZoneId': hosted_zone_id}
                if next_record_name:
                    params['StartRecordName'] = next_record_name
                if next_record_type:
                    params['StartRecordType'] = next_record_type
                
                response = self.route53_client.list_resource_record_sets(**params)
                
                for record_set in response.get('ResourceRecordSets', []):
                    record_sets.append(record_set)
                
                if response.get('IsTruncated'):
                    next_record_name = response.get('NextRecordName')
                    next_record_type = response.get('NextRecordType')
                else:
                    break

        except Exception as e:
            logger.error(f"获取托管区域 {hosted_zone_id} 的记录集失败: {str(e)}")

        return record_sets

    def get_domains(self) -> List[Dict[str, Any]]:
        """
        获取Route53注册的域名信息

        Returns:
            List[Dict[str, Any]]: 域名列表
        """
        logger.info("获取Route53注册的域名信息")
        domains = []

        try:
            # 获取所有注册的域名
            next_page_marker = None
            while True:
                if next_page_marker:
                    response = self.route53domains_client.list_domains(Marker=next_page_marker)
                else:
                    response = self.route53domains_client.list_domains()
                
                for domain in response.get('Domains', []):
                    domain_info = {
                        'DomainName': domain.get('DomainName'),
                        'AutoRenew': domain.get('AutoRenew'),
                        'TransferLock': domain.get('TransferLock'),
                        'Expiry': domain.get('Expiry'),
                    }
                    domains.append(domain_info)
                
                if 'NextPageMarker' in response:
                    next_page_marker = response['NextPageMarker']
                else:
                    break

        except Exception as e:
            logger.error(f"获取Route53注册的域名信息失败: {str(e)}")

        return domains

    def get_traffic_policies(self) -> List[Dict[str, Any]]:
        """
        获取Route53流量策略信息

        Returns:
            List[Dict[str, Any]]: 流量策略列表
        """
        logger.info("获取Route53流量策略信息")
        policies = []

        try:
            # 获取所有流量策略
            next_marker = None
            while True:
                if next_marker:
                    response = self.route53_client.list_traffic_policies(TrafficPolicyIdMarker=next_marker)
                else:
                    response = self.route53_client.list_traffic_policies()
                
                for policy in response.get('TrafficPolicySummaries', []):
                    policy_info = {
                        'Id': policy.get('Id'),
                        'Name': policy.get('Name'),
                        'Type': policy.get('Type'),
                        'LatestVersion': policy.get('LatestVersion'),
                        'TrafficPolicyCount': policy.get('TrafficPolicyCount'),
                    }
                    policies.append(policy_info)
                
                if response.get('IsTruncated'):
                    next_marker = response.get('TrafficPolicyIdMarker')
                else:
                    break

        except Exception as e:
            logger.error(f"获取Route53流量策略信息失败: {str(e)}")

        return policies

    def get_health_checks(self) -> List[Dict[str, Any]]:
        """
        获取Route53健康检查信息

        Returns:
            List[Dict[str, Any]]: 健康检查列表
        """
        logger.info("获取Route53健康检查信息")
        health_checks = []

        try:
            # 获取所有健康检查
            next_marker = None
            while True:
                if next_marker:
                    response = self.route53_client.list_health_checks(Marker=next_marker)
                else:
                    response = self.route53_client.list_health_checks()
                
                for health_check in response.get('HealthChecks', []):
                    health_check_info = {
                        'Id': health_check.get('Id'),
                        'CallerReference': health_check.get('CallerReference'),
                        'HealthCheckConfig': health_check.get('HealthCheckConfig'),
                        'HealthCheckVersion': health_check.get('HealthCheckVersion'),
                        'CloudWatchAlarmConfiguration': health_check.get('CloudWatchAlarmConfiguration'),
                        'LinkedService': health_check.get('LinkedService')
                    }
                    health_checks.append(health_check_info)
                
                if response.get('IsTruncated'):
                    next_marker = response.get('NextMarker')
                else:
                    break

        except Exception as e:
            logger.error(f"获取Route53健康检查信息失败: {str(e)}")

        return health_checks

    def get_query_logging_configs(self) -> List[Dict[str, Any]]:
        """
        获取Route53查询日志配置信息

        Returns:
            List[Dict[str, Any]]: 查询日志配置列表
        """
        logger.info("获取Route53查询日志配置信息")
        configs = []

        try:
            # 获取所有查询日志配置
            next_token = None
            while True:
                if next_token:
                    response = self.route53_client.list_query_logging_configs(NextToken=next_token)
                else:
                    response = self.route53_client.list_query_logging_configs()
                
                for config in response.get('QueryLoggingConfigs', []):
                    config_info = {
                        'Id': config.get('Id'),
                        'HostedZoneId': config.get('HostedZoneId'),
                        'CloudWatchLogsLogGroupArn': config.get('CloudWatchLogsLogGroupArn')
                    }
                    configs.append(config_info)
                
                if 'NextToken' in response:
                    next_token = response['NextToken']
                else:
                    break

        except Exception as e:
            logger.error(f"获取Route53查询日志配置信息失败: {str(e)}")

        return configs

    def get_resolver_endpoints(self) -> List[Dict[str, Any]]:
        """
        获取Route53 Resolver端点信息

        Returns:
            List[Dict[str, Any]]: Resolver端点列表
        """
        logger.info("获取Route53 Resolver端点信息")
        endpoints = []

        try:
            # 使用route53resolver客户端
            resolver_client = self.session.get_client('route53resolver')
            
            # 获取所有Resolver端点
            next_token = None
            while True:
                if next_token:
                    response = resolver_client.list_resolver_endpoints(NextToken=next_token)
                else:
                    response = resolver_client.list_resolver_endpoints()
                
                for endpoint in response.get('ResolverEndpoints', []):
                    endpoint_info = {
                        'Id': endpoint.get('Id'),
                        'CreatorRequestId': endpoint.get('CreatorRequestId'),
                        'Arn': endpoint.get('Arn'),
                        'Name': endpoint.get('Name'),
                        'SecurityGroupIds': endpoint.get('SecurityGroupIds'),
                        'Direction': endpoint.get('Direction'),
                        'IpAddressCount': endpoint.get('IpAddressCount'),
                        'HostVPCId': endpoint.get('HostVPCId'),
                        'Status': endpoint.get('Status'),
                        'StatusMessage': endpoint.get('StatusMessage'),
                        'CreationTime': endpoint.get('CreationTime'),
                        'ModificationTime': endpoint.get('ModificationTime')
                    }
                    endpoints.append(endpoint_info)
                
                if 'NextToken' in response:
                    next_token = response['NextToken']
                else:
                    break

        except Exception as e:
            logger.error(f"获取Route53 Resolver端点信息失败: {str(e)}")

        return endpoints

    def get_all_domain_router_global_assets(self) -> Dict[str, Any]:
        """
        获取所有Route53全局资源

        Returns:
            Dict[str, Any]: 所有Route53全局资源
        """
        logger.info("开始收集所有Route53全局资源")
        
        assets = {
            'hosted_zones': self.get_hosted_zones(),
            'record_sets': self.get_all_record_sets(),
            'domains': self.get_domains(),
            'traffic_policies': self.get_traffic_policies(),
            'health_checks': self.get_health_checks(),
            'query_logging_configs': self.get_query_logging_configs(),
            'resolver_endpoints': self.get_resolver_endpoints()
        }
        
        logger.info("Route53全局资源收集完成")
        return assets 