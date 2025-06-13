"""
腾讯云网络资产收集器

负责收集腾讯云的各种网络资源，包括：
- 私有网络 (VPC)
- 子网 (Subnet)
- 安全组 (Security Group)
- 负载均衡 (CLB)
- 弹性公网IP (EIP)
"""

import logging
from typing import Dict, Any, List
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.vpc.v20170312 import models as vpc_models
from tencentcloud.clb.v20180317 import models as clb_models

logger = logging.getLogger(__name__)

class NetworkAssetCollector:
    """网络资产收集器"""
    
    def __init__(self, session):
        """
        初始化网络资产收集器
        
        Args:
            session: 腾讯云会话对象
        """
        self.session = session
        
    def get_all_network_assets(self) -> Dict[str, Any]:
        """
        获取所有网络资产
        
        Returns:
            Dict[str, Any]: 包含所有网络资产的字典
        """
        logger.info("开始收集腾讯云网络资产")
        
        assets = {
            'vpcs': self.get_vpcs(),
            'subnets': self.get_subnets(),
            'route_tables': self.get_route_tables(),
            'security_groups': self.get_security_groups(),
            'network_acls': self.get_network_acls(),
            'load_balancers': self.get_load_balancers(),
            'eips': self.get_eips(),
            'nat_gateways': self.get_nat_gateways(),
        }
        
        logger.info("腾讯云网络资产收集完成")
        return assets
    
    def get_vpcs(self) -> List[Dict[str, Any]]:
        """
        获取VPC列表
        
        Returns:
            List[Dict[str, Any]]: VPC列表
        """
        logger.info("收集VPC")
        vpcs = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            vpc_client = self.session.get_client('vpc', region=region)
            req = vpc_models.DescribeVpcsRequest()
            
            resp = vpc_client.DescribeVpcs(req)
            
            if resp.VpcSet:
                for vpc in resp.VpcSet:
                    vpc_info = {
                        'region': region,
                        'vpc_id': vpc.VpcId,
                        'vpc_name': vpc.VpcName,
                        'cidr_block': vpc.CidrBlock,
                        'is_default': vpc.IsDefault,
                        'enable_multicast': vpc.EnableMulticast,
                        'dns_servers': vpc.DnsServerSet,
                        'domain_name': vpc.DomainName,
                        'dhcp_options_id': vpc.DhcpOptionsId,
                        'tags': [
                            {
                                'key': tag.Key,
                                'value': tag.Value,
                            } for tag in vpc.TagSet
                        ] if vpc.TagSet else [],
                        'created_time': vpc.CreatedTime,
                    }
                    vpcs.append(vpc_info)
                    
        except Exception as e:
            logger.error(f"获取VPC时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(vpcs)} 个VPC")
        return vpcs
    
    def get_subnets(self) -> List[Dict[str, Any]]:
        """
        获取子网列表
        
        Returns:
            List[Dict[str, Any]]: 子网列表
        """
        logger.info("收集子网")
        subnets = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            vpc_client = self.session.get_client('vpc', region=region)
            req = vpc_models.DescribeSubnetsRequest()
            
            resp = vpc_client.DescribeSubnets(req)
            
            if resp.SubnetSet:
                for subnet in resp.SubnetSet:
                    subnet_info = {
                        'region': region,
                        'vpc_id': subnet.VpcId,
                        'subnet_id': subnet.SubnetId,
                        'subnet_name': subnet.SubnetName,
                        'cidr_block': subnet.CidrBlock,
                        'is_default': subnet.IsDefault,
                        'enable_broadcast': subnet.EnableBroadcast,
                        'zone': subnet.Zone,
                        'route_table_id': subnet.RouteTableId,
                        'created_time': subnet.CreatedTime,
                        'available_ip_address_count': subnet.AvailableIpAddressCount,
                        'ipv6_cidr_block': subnet.Ipv6CidrBlock,
                        'network_acl_id': subnet.NetworkAclId,
                        'is_remote_vpc_snat': subnet.IsRemoteVpcSnat,
                        'tags': [
                            {
                                'key': tag.Key,
                                'value': tag.Value,
                            } for tag in subnet.TagSet
                        ] if subnet.TagSet else [],
                    }
                    subnets.append(subnet_info)
                    
        except Exception as e:
            logger.error(f"获取子网时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(subnets)} 个子网")
        return subnets
    
    def get_route_tables(self) -> List[Dict[str, Any]]:
        """
        获取路由表列表（包含详细的路由条目）
        
        Returns:
            List[Dict[str, Any]]: 路由表列表
        """
        logger.info("收集路由表")
        route_tables = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            vpc_client = self.session.get_client('vpc', region=region)
            req = vpc_models.DescribeRouteTablesRequest()
            
            resp = vpc_client.DescribeRouteTables(req)
            
            if resp.RouteTableSet:
                for rt in resp.RouteTableSet:
                    # 获取路由表的详细路由条目
                    route_table_id = getattr(rt, 'RouteTableId', None)
                    route_entries = self.get_route_table_entries(route_table_id) if route_table_id else []
                    
                    rt_info = {
                        'region': region,
                        'route_table_id': getattr(rt, 'RouteTableId', None),
                        'route_table_name': getattr(rt, 'RouteTableName', None),
                        'vpc_id': getattr(rt, 'VpcId', None),
                        'route_table_type': getattr(rt, 'RouteTableType', None),
                        'created_time': getattr(rt, 'CreatedTime', None),
                        'route_entries': route_entries,
                        'route_entries_count': len(route_entries),
                        'association_set': [
                            {
                                'subnet_id': getattr(assoc, 'SubnetId', None),
                                'route_table_id': getattr(assoc, 'RouteTableId', None),
                                'main': getattr(assoc, 'Main', None),
                            } for assoc in rt.AssociationSet
                        ] if getattr(rt, 'AssociationSet', None) else [],
                        'tags': [
                            {
                                'key': getattr(tag, 'Key', None),
                                'value': getattr(tag, 'Value', None),
                            } for tag in rt.TagSet
                        ] if getattr(rt, 'TagSet', None) else [],
                    }
                    route_tables.append(rt_info)
                    
        except Exception as e:
            logger.error(f"获取路由表时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(route_tables)} 个路由表")
        return route_tables
    
    def get_route_table_entries(self, route_table_id: str) -> List[Dict[str, Any]]:
        """
        获取路由表的具体路由条目
        
        Args:
            route_table_id: 路由表ID
            
        Returns:
            List[Dict[str, Any]]: 路由条目列表
        """
        entries = []
        
        if not route_table_id:
            return entries
        
        try:
            region = self.session.region
            vpc_client = self.session.get_client('vpc', region=region)
            req = vpc_models.DescribeRouteTablesRequest()
            req.RouteTableIds = [route_table_id]
            
            resp = vpc_client.DescribeRouteTables(req)
            
            if resp.RouteTableSet and getattr(resp.RouteTableSet[0], 'RouteSet', None):
                for route in resp.RouteTableSet[0].RouteSet:
                    entry_info = {
                        'route_id': getattr(route, 'RouteId', None),
                        'route_type': getattr(route, 'RouteType', None),
                        'destination_cidr_block': getattr(route, 'DestinationCidrBlock', None),
                        'destination_ipv6_cidr_block': getattr(route, 'DestinationIpv6CidrBlock', None),
                        'gateway_type': getattr(route, 'GatewayType', None),
                        'gateway_id': getattr(route, 'GatewayId', None),
                        'route_description': getattr(route, 'RouteDescription', None),
                        'enabled': getattr(route, 'Enabled', None),
                        'route_table_id': getattr(route, 'RouteTableId', None),
                        'published_to_vbc': getattr(route, 'PublishedToVbc', None),
                        'created_time': getattr(route, 'CreatedTime', None),
                    }
                    entries.append(entry_info)
                    
        except Exception as e:
            logger.debug(f"获取路由表 {route_table_id} 的路由条目失败: {str(e)}")
            
        return entries
    
    def get_security_groups(self) -> List[Dict[str, Any]]:
        """
        获取安全组列表（包含详细的安全组规则）
        
        Returns:
            List[Dict[str, Any]]: 安全组列表
        """
        logger.info("收集安全组")
        security_groups = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            vpc_client = self.session.get_client('vpc', region=region)
            req = vpc_models.DescribeSecurityGroupsRequest()
            
            resp = vpc_client.DescribeSecurityGroups(req)
            
            if resp.SecurityGroupSet:
                for sg in resp.SecurityGroupSet:
                    # 获取安全组的详细规则
                    inbound_rules = self.get_security_group_policies(sg.SecurityGroupId, 'ingress')
                    outbound_rules = self.get_security_group_policies(sg.SecurityGroupId, 'egress')
                    
                    sg_info = {
                        'region': region,
                        'security_group_id': sg.SecurityGroupId,
                        'security_group_name': sg.SecurityGroupName,
                        'security_group_desc': sg.SecurityGroupDesc,
                        'project_id': sg.ProjectId,
                        'is_default': sg.IsDefault,
                        'created_time': sg.CreatedTime,
                        'inbound_rules': inbound_rules,
                        'outbound_rules': outbound_rules,
                        'inbound_rules_count': len(inbound_rules),
                        'outbound_rules_count': len(outbound_rules),
                        'tags': [
                            {
                                'key': tag.Key,
                                'value': tag.Value,
                            } for tag in sg.TagSet
                        ] if sg.TagSet else [],
                    }
                    security_groups.append(sg_info)
                    
        except Exception as e:
            logger.error(f"获取安全组时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(security_groups)} 个安全组")
        return security_groups
    
    def get_security_group_policies(self, security_group_id: str, direction: str) -> List[Dict[str, Any]]:
        """
        获取安全组的具体策略规则
        
        Args:
            security_group_id: 安全组ID
            direction: 方向，'ingress'为入站，'egress'为出站
            
        Returns:
            List[Dict[str, Any]]: 安全组规则列表
        """
        rules = []
        
        try:
            region = self.session.region
            vpc_client = self.session.get_client('vpc', region=region)
            req = vpc_models.DescribeSecurityGroupPoliciesRequest()
            req.SecurityGroupId = security_group_id
            
            resp = vpc_client.DescribeSecurityGroupPolicies(req)
            
            # 根据方向选择规则集
            if direction == 'ingress' and resp.SecurityGroupPolicySet.Ingress:
                policy_set = resp.SecurityGroupPolicySet.Ingress
            elif direction == 'egress' and resp.SecurityGroupPolicySet.Egress:
                policy_set = resp.SecurityGroupPolicySet.Egress
            else:
                return rules
            
            for policy in policy_set:
                rule_info = {
                    'policy_index': policy.PolicyIndex,
                    'protocol': policy.Protocol,
                    'port': policy.Port,
                    'service_template': {
                        'service_id': policy.ServiceTemplate.ServiceId,
                        'service_group_id': policy.ServiceTemplate.ServiceGroupId,
                    } if policy.ServiceTemplate else None,
                    'cidr_block': policy.CidrBlock,
                    'ipv6_cidr_block': policy.Ipv6CidrBlock,
                    'security_group_id': policy.SecurityGroupId,
                    'address_template': {
                        'address_id': policy.AddressTemplate.AddressId,
                        'address_group_id': policy.AddressTemplate.AddressGroupId,
                    } if policy.AddressTemplate else None,
                    'action': policy.Action,
                    'policy_description': policy.PolicyDescription,
                    'modify_time': policy.ModifyTime,
                }
                rules.append(rule_info)
                
        except Exception as e:
            logger.debug(f"获取安全组 {security_group_id} 的 {direction} 规则失败: {str(e)}")
            
        return rules
    
    def get_load_balancers(self) -> List[Dict[str, Any]]:
        """
        获取负载均衡列表
        
        Returns:
            List[Dict[str, Any]]: 负载均衡列表
        """
        logger.info("收集负载均衡")
        load_balancers = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            clb_client = self.session.get_client('clb', region=region)
            req = clb_models.DescribeLoadBalancersRequest()
            
            resp = clb_client.DescribeLoadBalancers(req)
            
            if resp.LoadBalancerSet:
                for lb in resp.LoadBalancerSet:
                    lb_info = {
                        'region': region,
                        'load_balancer_id': lb.LoadBalancerId,
                        'load_balancer_name': lb.LoadBalancerName,
                        'load_balancer_type': lb.LoadBalancerType,
                        'forward': lb.Forward,
                        'domain': lb.Domain,
                        'vpc_id': lb.VpcId,
                        'subnet_id': lb.SubnetId,
                        'project_id': lb.ProjectId,
                        'address_ip_version': lb.AddressIPVersion,
                        'number': lb.Number,
                        'internet_charge_info': {
                            'internet_charge_type': lb.InternetChargeInfo.InternetChargeType,
                            'internet_max_bandwidth_out': lb.InternetChargeInfo.InternetMaxBandwidthOut,
                        } if lb.InternetChargeInfo else None,
                        'load_balancer_pass_to_target': lb.LoadBalancerPassToTarget,
                        'exclusive_cluster': {
                            'l4_clusters': lb.ExclusiveCluster.L4Clusters,
                            'l7_clusters': lb.ExclusiveCluster.L7Clusters,
                            'class_ical': lb.ExclusiveCluster.ClassicalCluster,
                        } if lb.ExclusiveCluster else None,
                        'address': lb.Address,
                        'bandwidth_package_id': lb.BandwidthPackageId,
                        'tags': [
                            {
                                'key': tag.Key,
                                'value': tag.Value,
                            } for tag in lb.Tags
                        ] if lb.Tags else [],
                        'create_time': lb.CreateTime,
                        'charge_type': lb.ChargeType,
                        'network_attributes': {
                            'internet_charge_type': lb.NetworkAttributes.InternetChargeType,
                            'internet_max_bandwidth_out': lb.NetworkAttributes.InternetMaxBandwidthOut,
                        } if lb.NetworkAttributes else None,
                    }
                    load_balancers.append(lb_info)
                    
        except Exception as e:
            logger.error(f"获取负载均衡时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(load_balancers)} 个负载均衡")
        return load_balancers
    
    def get_eips(self) -> List[Dict[str, Any]]:
        """
        获取弹性公网IP列表
        
        Returns:
            List[Dict[str, Any]]: 弹性公网IP列表
        """
        logger.info("收集弹性公网IP")
        eips = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            vpc_client = self.session.get_client('vpc', region=region)
            req = vpc_models.DescribeAddressesRequest()
            
            resp = vpc_client.DescribeAddresses(req)
            
            if resp.AddressSet:
                for eip in resp.AddressSet:
                    eip_info = {
                        'region': region,
                        'address_id': eip.AddressId,
                        'address_name': eip.AddressName,
                        'address_status': eip.AddressStatus,
                        'address_ip': eip.AddressIp,
                        'address_type': eip.AddressType,
                        'internet_charge_type': eip.InternetChargeType,
                        'internet_max_bandwidth_out': eip.InternetMaxBandwidthOut,
                        'instance_type': eip.InstanceType,
                        'instance_id': eip.InstanceId,
                        'network_interface_id': eip.NetworkInterfaceId,
                        'private_address_ip': eip.PrivateAddressIp,
                        'is_arrears': eip.IsArrears,
                        'is_blocked': eip.IsBlocked,
                        'is_eip': eip.IsEip,
                        'created_time': eip.CreatedTime,
                        'tags': [
                            {
                                'key': tag.Key,
                                'value': tag.Value,
                            } for tag in eip.TagSet
                        ] if eip.TagSet else [],
                    }
                    eips.append(eip_info)
                    
        except Exception as e:
            logger.error(f"获取弹性公网IP时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(eips)} 个弹性公网IP")
        return eips
    
    def get_nat_gateways(self) -> List[Dict[str, Any]]:
        """
        获取NAT网关列表
        
        Returns:
            List[Dict[str, Any]]: NAT网关列表
        """
        logger.info("收集NAT网关")
        nat_gateways = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            vpc_client = self.session.get_client('vpc', region=region)
            req = vpc_models.DescribeNatGatewaysRequest()
            
            resp = vpc_client.DescribeNatGateways(req)
            
            if resp.NatGatewaySet:
                for nat in resp.NatGatewaySet:
                    nat_info = {
                        'region': region,
                        'nat_gateway_id': nat.NatGatewayId,
                        'nat_gateway_name': nat.NatGatewayName,
                        'created_time': nat.CreatedTime,
                        'state': nat.State,
                        'internet_max_bandwidth_out': nat.InternetMaxBandwidthOut,
                        'max_concurrent_connection': nat.MaxConcurrentConnection,
                        'public_ip_address_set': nat.PublicIpAddressSet,
                        'network_state': nat.NetworkState,
                        'destination_ip_port_translation_nat_rule_set': nat.DestinationIpPortTranslationNatRuleSet,
                        'vpc_id': nat.VpcId,
                        'zone': nat.Zone,
                        'tags': [
                            {
                                'key': tag.Key,
                                'value': tag.Value,
                            } for tag in nat.TagSet
                        ] if nat.TagSet else [],
                    }
                    nat_gateways.append(nat_info)
                    
        except Exception as e:
            logger.error(f"获取NAT网关时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(nat_gateways)} 个NAT网关")
        return nat_gateways
    
    def get_network_acls(self) -> List[Dict[str, Any]]:
        """
        获取网络ACL列表（包含详细的ACL规则）
        
        Returns:
            List[Dict[str, Any]]: 网络ACL列表
        """
        logger.info("收集网络ACL")
        network_acls = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            vpc_client = self.session.get_client('vpc', region=region)
            req = vpc_models.DescribeNetworkAclsRequest()
            
            resp = vpc_client.DescribeNetworkAcls(req)
            
            if resp.NetworkAclSet:
                for acl in resp.NetworkAclSet:
                    # 获取ACL的详细规则
                    inbound_entries = self.get_network_acl_entries(acl.NetworkAclId, 'ingress')
                    outbound_entries = self.get_network_acl_entries(acl.NetworkAclId, 'egress')
                    
                    acl_info = {
                        'region': region,
                        'network_acl_id': acl.NetworkAclId,
                        'network_acl_name': acl.NetworkAclName,
                        'vpc_id': acl.VpcId,
                        'subnet_ids': acl.SubnetIds if acl.SubnetIds else [],
                        'created_time': acl.CreatedTime,
                        'inbound_entries': inbound_entries,
                        'outbound_entries': outbound_entries,
                        'inbound_entries_count': len(inbound_entries),
                        'outbound_entries_count': len(outbound_entries),
                        'tags': [
                            {
                                'key': tag.Key,
                                'value': tag.Value,
                            } for tag in acl.TagSet
                        ] if acl.TagSet else [],
                    }
                    network_acls.append(acl_info)
                    
        except Exception as e:
            logger.error(f"获取网络ACL时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(network_acls)} 个网络ACL")
        return network_acls
    
    def get_network_acl_entries(self, network_acl_id: str, direction: str) -> List[Dict[str, Any]]:
        """
        获取网络ACL的具体条目规则
        
        Args:
            network_acl_id: 网络ACL ID
            direction: 方向，'ingress'为入站，'egress'为出站
            
        Returns:
            List[Dict[str, Any]]: 网络ACL条目列表
        """
        entries = []
        
        try:
            region = self.session.region
            vpc_client = self.session.get_client('vpc', region=region)
            req = vpc_models.DescribeNetworkAclEntriesRequest()
            req.NetworkAclId = network_acl_id
            req.Direction = direction
            
            resp = vpc_client.DescribeNetworkAclEntries(req)
            
            if resp.NetworkAclEntrySet:
                for entry in resp.NetworkAclEntrySet:
                    entry_info = {
                        'network_acl_entry_id': entry.NetworkAclEntryId,
                        'protocol': entry.Protocol,
                        'port': entry.Port,
                        'cidr_block': entry.CidrBlock,
                        'ipv6_cidr_block': entry.Ipv6CidrBlock,
                        'action': entry.Action,
                        'network_acl_entry_description': entry.NetworkAclEntryDescription,
                        'modify_time': entry.ModifyTime,
                        'created_time': entry.CreatedTime,
                    }
                    entries.append(entry_info)
                    
        except Exception as e:
            logger.debug(f"获取网络ACL {network_acl_id} 的 {direction} 条目失败: {str(e)}")
            
        return entries 