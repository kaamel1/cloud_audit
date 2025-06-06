"""
AWS网络资源处理模块，负责获取VPC、安全组等网络资源信息。
"""
import boto3
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class NetworkAssetCollector:
    """AWS网络资源收集器"""

    def __init__(self, session):
        """
        初始化网络资源收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        self.ec2_client = session.get_client('ec2')

    def get_vpcs(self) -> List[Dict[str, Any]]:
        """
        获取VPC信息

        Returns:
            List[Dict[str, Any]]: VPC列表
        """
        logger.info("获取VPC信息")
        vpcs = []

        try:
            # 获取所有VPC
            response = self.ec2_client.describe_vpcs()

            for vpc in response.get('Vpcs', []):
                vpc_info = {
                    'VpcId': vpc.get('VpcId'),
                    'CidrBlock': vpc.get('CidrBlock'),
                    'State': vpc.get('State'),
                    'IsDefault': vpc.get('IsDefault'),
                    'Tags': vpc.get('Tags', []),
                    'DhcpOptionsId': vpc.get('DhcpOptionsId'),
                    'InstanceTenancy': vpc.get('InstanceTenancy'),
                    'CidrBlockAssociationSet': vpc.get('CidrBlockAssociationSet', []),
                    'Ipv6CidrBlockAssociationSet': vpc.get('Ipv6CidrBlockAssociationSet', []),
                }
                vpcs.append(vpc_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpcs(
                    NextToken=response['NextToken']
                )

                for vpc in response.get('Vpcs', []):
                    vpc_info = {
                        'VpcId': vpc.get('VpcId'),
                        'CidrBlock': vpc.get('CidrBlock'),
                        'State': vpc.get('State'),
                        'IsDefault': vpc.get('IsDefault'),
                        'Tags': vpc.get('Tags', []),
                        'DhcpOptionsId': vpc.get('DhcpOptionsId'),
                        'InstanceTenancy': vpc.get('InstanceTenancy'),
                        'CidrBlockAssociationSet': vpc.get('CidrBlockAssociationSet', []),
                        'Ipv6CidrBlockAssociationSet': vpc.get('Ipv6CidrBlockAssociationSet', []),
                    }
                    vpcs.append(vpc_info)

        except Exception as e:
            logger.error(f"获取VPC信息失败: {str(e)}")

        return vpcs

    def get_subnets(self) -> List[Dict[str, Any]]:
        """
        获取子网信息

        Returns:
            List[Dict[str, Any]]: 子网列表
        """
        logger.info("获取子网信息")
        subnets = []

        try:
            # 获取所有子网
            response = self.ec2_client.describe_subnets()

            for subnet in response.get('Subnets', []):
                subnet_info = {
                    'SubnetId': subnet.get('SubnetId'),
                    'VpcId': subnet.get('VpcId'),
                    'CidrBlock': subnet.get('CidrBlock'),
                    'AvailabilityZone': subnet.get('AvailabilityZone'),
                    'State': subnet.get('State'),
                    'AvailableIpAddressCount': subnet.get('AvailableIpAddressCount'),
                    'DefaultForAz': subnet.get('DefaultForAz'),
                    'MapPublicIpOnLaunch': subnet.get('MapPublicIpOnLaunch'),
                    'AssignIpv6AddressOnCreation': subnet.get('AssignIpv6AddressOnCreation'),
                    'Ipv6CidrBlockAssociationSet': subnet.get('Ipv6CidrBlockAssociationSet', []),
                    'Tags': subnet.get('Tags', []),
                }
                subnets.append(subnet_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_subnets(
                    NextToken=response['NextToken']
                )

                for subnet in response.get('Subnets', []):
                    subnet_info = {
                        'SubnetId': subnet.get('SubnetId'),
                        'VpcId': subnet.get('VpcId'),
                        'CidrBlock': subnet.get('CidrBlock'),
                        'AvailabilityZone': subnet.get('AvailabilityZone'),
                        'State': subnet.get('State'),
                        'AvailableIpAddressCount': subnet.get('AvailableIpAddressCount'),
                        'DefaultForAz': subnet.get('DefaultForAz'),
                        'MapPublicIpOnLaunch': subnet.get('MapPublicIpOnLaunch'),
                        'AssignIpv6AddressOnCreation': subnet.get('AssignIpv6AddressOnCreation'),
                        'Ipv6CidrBlockAssociationSet': subnet.get('Ipv6CidrBlockAssociationSet', []),
                        'Tags': subnet.get('Tags', []),
                    }
                    subnets.append(subnet_info)

        except Exception as e:
            logger.error(f"获取子网信息失败: {str(e)}")

        return subnets

    def get_security_groups(self) -> List[Dict[str, Any]]:
        """
        获取安全组信息

        Returns:
            List[Dict[str, Any]]: 安全组列表
        """
        logger.info("获取安全组信息")
        security_groups = []

        try:
            # 获取所有安全组
            response = self.ec2_client.describe_security_groups()

            for sg in response.get('SecurityGroups', []):
                sg_info = {
                    'GroupId': sg.get('GroupId'),
                    'GroupName': sg.get('GroupName'),
                    'Description': sg.get('Description'),
                    'VpcId': sg.get('VpcId'),
                    'IpPermissions': sg.get('IpPermissions', []),
                    'IpPermissionsEgress': sg.get('IpPermissionsEgress', []),
                    'Tags': sg.get('Tags', []),
                }
                security_groups.append(sg_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_security_groups(
                    NextToken=response['NextToken']
                )

                for sg in response.get('SecurityGroups', []):
                    sg_info = {
                        'GroupId': sg.get('GroupId'),
                        'GroupName': sg.get('GroupName'),
                        'Description': sg.get('Description'),
                        'VpcId': sg.get('VpcId'),
                        'IpPermissions': sg.get('IpPermissions', []),
                        'IpPermissionsEgress': sg.get('IpPermissionsEgress', []),
                        'Tags': sg.get('Tags', []),
                    }
                    security_groups.append(sg_info)

        except Exception as e:
            logger.error(f"获取安全组信息失败: {str(e)}")

        return security_groups

    def get_route_tables(self) -> List[Dict[str, Any]]:
        """
        获取路由表信息

        Returns:
            List[Dict[str, Any]]: 路由表列表
        """
        logger.info("获取路由表信息")
        route_tables = []

        try:
            # 获取所有路由表
            response = self.ec2_client.describe_route_tables()

            for rt in response.get('RouteTables', []):
                rt_info = {
                    'RouteTableId': rt.get('RouteTableId'),
                    'VpcId': rt.get('VpcId'),
                    'Routes': rt.get('Routes', []),
                    'Associations': rt.get('Associations', []),
                    'PropagatingVgws': rt.get('PropagatingVgws', []),
                    'Tags': rt.get('Tags', []),
                }
                route_tables.append(rt_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_route_tables(
                    NextToken=response['NextToken']
                )

                for rt in response.get('RouteTables', []):
                    rt_info = {
                        'RouteTableId': rt.get('RouteTableId'),
                        'VpcId': rt.get('VpcId'),
                        'Routes': rt.get('Routes', []),
                        'Associations': rt.get('Associations', []),
                        'PropagatingVgws': rt.get('PropagatingVgws', []),
                        'Tags': rt.get('Tags', []),
                    }
                    route_tables.append(rt_info)

        except Exception as e:
            logger.error(f"获取路由表信息失败: {str(e)}")

        return route_tables

    def get_vpc_peering_connections(self) -> List[Dict[str, Any]]:
        """
        获取VPC对等连接信息

        Returns:
            List[Dict[str, Any]]: VPC对等连接列表
        """
        logger.info("获取VPC对等连接信息")
        peering_connections = []

        try:
            # 获取所有VPC对等连接
            response = self.ec2_client.describe_vpc_peering_connections()

            for peering in response.get('VpcPeeringConnections', []):
                peering_info = {
                    'VpcPeeringConnectionId': peering.get('VpcPeeringConnectionId'),
                    'Status': peering.get('Status', {}),
                    'RequesterVpcInfo': peering.get('RequesterVpcInfo', {}),  # 包含Region字段
                    'AccepterVpcInfo': peering.get('AccepterVpcInfo', {}),    # 包含Region字段
                    'Tags': peering.get('Tags', []),
                }
                peering_connections.append(peering_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpc_peering_connections(
                    NextToken=response['NextToken']
                )

                for peering in response.get('VpcPeeringConnections', []):
                    peering_info = {
                        'VpcPeeringConnectionId': peering.get('VpcPeeringConnectionId'),
                        'Status': peering.get('Status', {}),
                        'RequesterVpcInfo': peering.get('RequesterVpcInfo', {}),
                        'AccepterVpcInfo': peering.get('AccepterVpcInfo', {}),
                        'Tags': peering.get('Tags', []),
                    }
                    peering_connections.append(peering_info)

        except Exception as e:
            logger.error(f"获取VPC对等连接信息失败: {str(e)}")

        return peering_connections

    def get_network_acls(self) -> List[Dict[str, Any]]:
        """
        获取网络ACL信息

        Returns:
            List[Dict[str, Any]]: 网络ACL列表
        """
        logger.info("获取网络ACL信息")
        acls = []

        try:
            # 获取所有网络ACL
            response = self.ec2_client.describe_network_acls()

            for acl in response.get('NetworkAcls', []):
                acl_info = {
                    'NetworkAclId': acl.get('NetworkAclId'),
                    'VpcId': acl.get('VpcId'),
                    'IsDefault': acl.get('IsDefault'),
                    'Entries': acl.get('Entries', []),
                    'Associations': acl.get('Associations', []),
                    'Tags': acl.get('Tags', []),
                }
                acls.append(acl_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_network_acls(
                    NextToken=response['NextToken']
                )

                for acl in response.get('NetworkAcls', []):
                    acl_info = {
                        'NetworkAclId': acl.get('NetworkAqlId'),
                        'VpcId': acl.get('VpcId'),
                        'IsDefault': acl.get('IsDefault'),
                        'Entries': acl.get('Entries', []),
                        'Associations': acl.get('Associations', []),
                        'Tags': acl.get('Tags', []),
                    }
                    acls.append(acl_info)

        except Exception as e:
            logger.error(f"获取网络ACL信息失败: {str(e)}")

        return acls

    def get_internet_gateways(self) -> List[Dict[str, Any]]:
        """
        获取互联网网关信息

        Returns:
            List[Dict[str, Any]]: 互联网网关列表
        """
        logger.info("获取互联网网关信息")
        internet_gateways = []

        try:
            # 获取所有互联网网关
            response = self.ec2_client.describe_internet_gateways()

            for igw in response.get('InternetGateways', []):
                igw_info = {
                    'InternetGatewayId': igw.get('InternetGatewayId'),
                    'Attachments': igw.get('Attachments', []),
                    'Tags': igw.get('Tags', []),
                }
                internet_gateways.append(igw_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_internet_gateways(
                    NextToken=response['NextToken']
                )

                for igw in response.get('InternetGateways', []):
                    igw_info = {
                        'InternetGatewayId': igw.get('InternetGatewayId'),
                        'Attachments': igw.get('Attachments', []),
                        'Tags': igw.get('Tags', []),
                    }
                    internet_gateways.append(igw_info)

        except Exception as e:
            logger.error(f"获取互联网网关信息失败: {str(e)}")

        return internet_gateways

    def get_nat_gateways(self) -> List[Dict[str, Any]]:
        """
        获取NAT网关信息

        Returns:
            List[Dict[str, Any]]: NAT网关列表
        """
        logger.info("获取NAT网关信息")
        nat_gateways = []

        try:
            # 获取所有NAT网关
            response = self.ec2_client.describe_nat_gateways()

            for ngw in response.get('NatGateways', []):
                ngw_info = {
                    'NatGatewayId': ngw.get('NatGatewayId'),
                    'SubnetId': ngw.get('SubnetId'),
                    'VpcId': ngw.get('VpcId'),
                    'State': ngw.get('State'),
                    'NatGatewayAddresses': ngw.get('NatGatewayAddresses', []),
                    'CreationTime': ngw.get('CreationTime'),
                    'Tags': ngw.get('Tags', []),
                }
                nat_gateways.append(ngw_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_nat_gateways(
                    NextToken=response['NextToken']
                )

                for ngw in response.get('NatGateways', []):
                    ngw_info = {
                        'NatGatewayId': ngw.get('NatGatewayId'),
                        'SubnetId': ngw.get('SubnetId'),
                        'VpcId': ngw.get('VpcId'),
                        'State': ngw.get('State'),
                        'NatGatewayAddresses': ngw.get('NatGatewayAddresses', []),
                        'CreationTime': ngw.get('CreationTime'),
                        'Tags': ngw.get('Tags', []),
                    }
                    nat_gateways.append(ngw_info)

        except Exception as e:
            logger.error(f"获取NAT网关信息失败: {str(e)}")

        return nat_gateways

    def get_vpc_endpoints(self) -> List[Dict[str, Any]]:
        """
        获取VPC端点信息

        Returns:
            List[Dict[str, Any]]: VPC端点列表
        """
        logger.info("获取VPC端点信息")
        vpc_endpoints = []

        try:
            # 获取所有VPC端点
            response = self.ec2_client.describe_vpc_endpoints()

            for endpoint in response.get('VpcEndpoints', []):
                endpoint_info = {
                    'VpcEndpointId': endpoint.get('VpcEndpointId'),
                    'VpcEndpointType': endpoint.get('VpcEndpointType'),
                    'VpcId': endpoint.get('VpcId'),
                    'ServiceName': endpoint.get('ServiceName'),
                    'State': endpoint.get('State'),
                    'PolicyDocument': endpoint.get('PolicyDocument'),
                    'RouteTableIds': endpoint.get('RouteTableIds', []),
                    'SubnetIds': endpoint.get('SubnetIds', []),
                    'Groups': endpoint.get('Groups', []),
                    'PrivateDnsEnabled': endpoint.get('PrivateDnsEnabled'),
                    'Tags': endpoint.get('Tags', []),
                }
                vpc_endpoints.append(endpoint_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpc_endpoints(
                    NextToken=response['NextToken']
                )

                for endpoint in response.get('VpcEndpoints', []):
                    endpoint_info = {
                        'VpcEndpointId': endpoint.get('VpcEndpointId'),
                        'VpcEndpointType': endpoint.get('VpcEndpointType'),
                        'VpcId': endpoint.get('VpcId'),
                        'ServiceName': endpoint.get('ServiceName'),
                        'State': endpoint.get('State'),
                        'PolicyDocument': endpoint.get('PolicyDocument'),
                        'RouteTableIds': endpoint.get('RouteTableIds', []),
                        'SubnetIds': endpoint.get('SubnetIds', []),
                        'Groups': endpoint.get('Groups', []),
                        'PrivateDnsEnabled': endpoint.get('PrivateDnsEnabled'),
                        'Tags': endpoint.get('Tags', []),
                    }
                    vpc_endpoints.append(endpoint_info)

        except Exception as e:
            logger.error(f"获取VPC端点信息失败: {str(e)}")

        return vpc_endpoints

    def get_all_network_assets(self) -> Dict[str, Dict[str, Any]]:
        """
        获取所有网络资源

        Returns:
            Dict[str, Dict[str, Any]]: 所有网络资源
        """
        network_assets = {
            'vpcs': {vpc.get('VpcId'): vpc for vpc in self.get_vpcs()},
            'subnets': {subnet.get('SubnetId'): subnet for subnet in self.get_subnets()},
            'security_groups': {sg.get('GroupId'): sg for sg in self.get_security_groups()},
            'route_tables': {rt.get('RouteTableId'): rt for rt in self.get_route_tables()},
            'vpc_peering_connections': {vpc_peering.get('VpcPeeringConnectionId'): vpc_peering 
                                       for vpc_peering in self.get_vpc_peering_connections()},
            'network_acls': {acl.get('NetworkAclId'): acl for acl in self.get_network_acls()},
            'internet_gateways': {igw.get('InternetGatewayId'): igw for igw in self.get_internet_gateways()},
            'nat_gateways': {ngw.get('NatGatewayId'): ngw for ngw in self.get_nat_gateways()},
            'vpc_endpoints': {endpoint.get('VpcEndpointId'): endpoint for endpoint in self.get_vpc_endpoints()},
        }

        return network_assets
