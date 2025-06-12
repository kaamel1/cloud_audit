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
            'security_groups': self.get_security_groups(),
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
    
    def get_security_groups(self) -> List[Dict[str, Any]]:
        """
        获取安全组列表
        
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
                    sg_info = {
                        'region': region,
                        'security_group_id': sg.SecurityGroupId,
                        'security_group_name': sg.SecurityGroupName,
                        'security_group_desc': sg.SecurityGroupDesc,
                        'project_id': sg.ProjectId,
                        'is_default': sg.IsDefault,
                        'created_time': sg.CreatedTime,
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