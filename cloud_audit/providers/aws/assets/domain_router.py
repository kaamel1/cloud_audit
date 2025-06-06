"""
AWS域名与路由处理模块，负责获取Route53域名、记录集等信息。
"""
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class DomainRouterAssetCollector:
    """AWS域名与路由资源收集器"""

    def __init__(self, session):
        """
        初始化域名与路由资源收集器

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

            # 处理分页
            while response.get('IsTruncated', False):
                response = self.route53_client.list_hosted_zones(
                    Marker=response['NextMarker']
                )

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

        except Exception as e:
            logger.error(f"获取Route53托管区域信息失败: {str(e)}")

        return zones

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
            response = self.route53_client.list_resource_record_sets(
                HostedZoneId=hosted_zone_id
            )

            for record_set in response.get('ResourceRecordSets', []):
                record_sets.append(record_set)

            # 处理分页
            while response.get('IsTruncated', False):
                response = self.route53_client.list_resource_record_sets(
                    HostedZoneId=hosted_zone_id,
                    StartRecordName=response['NextRecordName'],
                    StartRecordType=response['NextRecordType']
                )

                for record_set in response.get('ResourceRecordSets', []):
                    record_sets.append(record_set)

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
            response = self.route53domains_client.list_domains()

            for domain in response.get('Domains', []):
                domain_info = {
                    'DomainName': domain.get('DomainName'),
                    'AutoRenew': domain.get('AutoRenew'),
                    'TransferLock': domain.get('TransferLock'),
                    'Expiry': domain.get('Expiry'),
                }
                domains.append(domain_info)

            # 处理分页
            while 'NextPageMarker' in response:
                response = self.route53domains_client.list_domains(
                    Marker=response['NextPageMarker']
                )

                for domain in response.get('Domains', []):
                    domain_info = {
                        'DomainName': domain.get('DomainName'),
                        'AutoRenew': domain.get('AutoRenew'),
                        'TransferLock': domain.get('TransferLock'),
                        'Expiry': domain.get('Expiry'),
                    }
                    domains.append(domain_info)

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

            # 处理分页
            while 'TrafficPolicyIdMarker' in response:
                response = self.route53_client.list_traffic_policies(
                    TrafficPolicyIdMarker=response['TrafficPolicyIdMarker']
                )

                for policy in response.get('TrafficPolicySummaries', []):
                    policy_info = {
                        'Id': policy.get('Id'),
                        'Name': policy.get('Name'),
                        'Type': policy.get('Type'),
                        'LatestVersion': policy.get('LatestVersion'),
                        'TrafficPolicyCount': policy.get('TrafficPolicyCount'),
                    }
                    policies.append(policy_info)

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
            response = self.route53_client.list_health_checks()

            for check in response.get('HealthChecks', []):
                health_checks.append(check)

            # 处理分页
            while 'Marker' in response:
                response = self.route53_client.list_health_checks(
                    Marker=response['Marker']
                )

                for check in response.get('HealthChecks', []):
                    health_checks.append(check)

        except Exception as e:
            logger.error(f"获取Route53健康检查信息失败: {str(e)}")

        return health_checks

    def get_all_domain_router_assets(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        获取所有域名与路由资源，按类型分开并返回单个资源项

        Returns:
            Dict[str, Dict[str, Dict[str, Any]]]: 按类型分开的域名与路由资源，每个资源项单独存储
        """
        # 获取托管区域
        hosted_zones = {zone['Id']: zone for zone in self.get_hosted_zones()}
        
        # 获取记录集（按托管区域分组）
        record_sets = {}
        for zone_id in hosted_zones.keys():
            zone_records = self.get_record_sets(zone_id)
            record_sets[zone_id] = {f"{record.get('Name')}_{record.get('Type')}": record for record in zone_records}
        
        # 获取注册的域名
        domains = {domain['DomainName']: domain for domain in self.get_domains()}
        
        # 获取流量策略
        traffic_policies = {policy['Id']: policy for policy in self.get_traffic_policies()}
        
        # 获取健康检查
        health_checks = {check['Id']: check for check in self.get_health_checks()}
        
        return {
            'hosted_zones': hosted_zones,
            'record_sets': record_sets,
            'domains': domains,
            'traffic_policies': traffic_policies,
            'health_checks': health_checks
        } 