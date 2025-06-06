"""
AWS Transit Gateway及高级网络资源处理模块，负责获取Transit Gateway、PrivateLink等网络资源信息。
"""
import boto3
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class TransitGatewayAssetCollector:
    """AWS Transit Gateway及高级网络资源收集器"""

    def __init__(self, session):
        """
        初始化Transit Gateway及高级网络资源收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        self.ec2_client = session.get_client('ec2')
        self.networkfirewall_client = session.get_client('network-firewall')
        self.global_accelerator_client = session.get_client('globalaccelerator')
        self.directconnect_client = session.get_client('directconnect')

    def get_transit_gateways(self) -> List[Dict[str, Any]]:
        """
        获取Transit Gateway信息

        Returns:
            List[Dict[str, Any]]: Transit Gateway列表
        """
        logger.info("获取Transit Gateway信息")
        transit_gateways = []

        try:
            # 获取所有Transit Gateway
            response = self.ec2_client.describe_transit_gateways()

            for tgw in response.get('TransitGateways', []):
                tgw_info = {
                    'TransitGatewayId': tgw.get('TransitGatewayId'),
                    'TransitGatewayArn': tgw.get('TransitGatewayArn'),
                    'State': tgw.get('State'),
                    'OwnerId': tgw.get('OwnerId'),
                    'Description': tgw.get('Description'),
                    'CreationTime': tgw.get('CreationTime'),
                    'Options': tgw.get('Options', {}),
                    'Tags': tgw.get('Tags', []),
                }
                transit_gateways.append(tgw_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_transit_gateways(
                    NextToken=response['NextToken']
                )

                for tgw in response.get('TransitGateways', []):
                    tgw_info = {
                        'TransitGatewayId': tgw.get('TransitGatewayId'),
                        'TransitGatewayArn': tgw.get('TransitGatewayArn'),
                        'State': tgw.get('State'),
                        'OwnerId': tgw.get('OwnerId'),
                        'Description': tgw.get('Description'),
                        'CreationTime': tgw.get('CreationTime'),
                        'Options': tgw.get('Options', {}),
                        'Tags': tgw.get('Tags', []),
                    }
                    transit_gateways.append(tgw_info)

        except Exception as e:
            logger.error(f"获取Transit Gateway信息失败: {str(e)}")

        return transit_gateways

    def get_transit_gateway_attachments(self) -> List[Dict[str, Any]]:
        """
        获取Transit Gateway附件信息

        Returns:
            List[Dict[str, Any]]: Transit Gateway附件列表
        """
        logger.info("获取Transit Gateway附件信息")
        attachments = []

        try:
            # 获取所有Transit Gateway附件
            response = self.ec2_client.describe_transit_gateway_attachments()

            for attachment in response.get('TransitGatewayAttachments', []):
                attachment_info = {
                    'TransitGatewayAttachmentId': attachment.get('TransitGatewayAttachmentId'),
                    'TransitGatewayId': attachment.get('TransitGatewayId'),
                    'ResourceOwnerId': attachment.get('ResourceOwnerId'),
                    'ResourceType': attachment.get('ResourceType'),
                    'ResourceId': attachment.get('ResourceId'),
                    'State': attachment.get('State'),
                    'Association': attachment.get('Association', {}),
                    'CreationTime': attachment.get('CreationTime'),
                    'Tags': attachment.get('Tags', []),
                }
                attachments.append(attachment_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_transit_gateway_attachments(
                    NextToken=response['NextToken']
                )

                for attachment in response.get('TransitGatewayAttachments', []):
                    attachment_info = {
                        'TransitGatewayAttachmentId': attachment.get('TransitGatewayAttachmentId'),
                        'TransitGatewayId': attachment.get('TransitGatewayId'),
                        'ResourceOwnerId': attachment.get('ResourceOwnerId'),
                        'ResourceType': attachment.get('ResourceType'),
                        'ResourceId': attachment.get('ResourceId'),
                        'State': attachment.get('State'),
                        'Association': attachment.get('Association', {}),
                        'CreationTime': attachment.get('CreationTime'),
                        'Tags': attachment.get('Tags', []),
                    }
                    attachments.append(attachment_info)

        except Exception as e:
            logger.error(f"获取Transit Gateway附件信息失败: {str(e)}")

        return attachments

    def get_transit_gateway_route_tables(self) -> List[Dict[str, Any]]:
        """
        获取Transit Gateway路由表信息

        Returns:
            List[Dict[str, Any]]: Transit Gateway路由表列表
        """
        logger.info("获取Transit Gateway路由表信息")
        route_tables = []

        try:
            # 获取所有Transit Gateway路由表
            response = self.ec2_client.describe_transit_gateway_route_tables()

            for rt in response.get('TransitGatewayRouteTables', []):
                rt_info = {
                    'TransitGatewayRouteTableId': rt.get('TransitGatewayRouteTableId'),
                    'TransitGatewayId': rt.get('TransitGatewayId'),
                    'State': rt.get('State'),
                    'DefaultAssociationRouteTable': rt.get('DefaultAssociationRouteTable'),
                    'DefaultPropagationRouteTable': rt.get('DefaultPropagationRouteTable'),
                    'CreationTime': rt.get('CreationTime'),
                    'Tags': rt.get('Tags', []),
                }
                route_tables.append(rt_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.ec2_client.describe_transit_gateway_route_tables(
                    NextToken=response['NextToken']
                )

                for rt in response.get('TransitGatewayRouteTables', []):
                    rt_info = {
                        'TransitGatewayRouteTableId': rt.get('TransitGatewayRouteTableId'),
                        'TransitGatewayId': rt.get('TransitGatewayId'),
                        'State': rt.get('State'),
                        'DefaultAssociationRouteTable': rt.get('DefaultAssociationRouteTable'),
                        'DefaultPropagationRouteTable': rt.get('DefaultPropagationRouteTable'),
                        'CreationTime': rt.get('CreationTime'),
                        'Tags': rt.get('Tags', []),
                    }
                    route_tables.append(rt_info)

        except Exception as e:
            logger.error(f"获取Transit Gateway路由表信息失败: {str(e)}")

        return route_tables

    def get_network_firewalls(self) -> List[Dict[str, Any]]:
        """
        获取Network Firewall信息

        Returns:
            List[Dict[str, Any]]: Network Firewall列表
        """
        logger.info("获取Network Firewall信息")
        firewalls = []

        try:
            # 获取所有Network Firewall
            response = self.networkfirewall_client.list_firewalls()

            for fw in response.get('Firewalls', []):
                # 获取防火墙详细信息
                try:
                    fw_detail = self.networkfirewall_client.describe_firewall(
                        FirewallName=fw.get('FirewallName'),
                        FirewallArn=fw.get('FirewallArn')
                    )
                    firewall_detail = fw_detail.get('Firewall', {})
                    firewall_status = fw_detail.get('FirewallStatus', {})
                    
                    fw_info = {
                        'FirewallName': firewall_detail.get('FirewallName'),
                        'FirewallArn': firewall_detail.get('FirewallArn'),
                        'FirewallPolicyArn': firewall_detail.get('FirewallPolicyArn'),
                        'VpcId': firewall_detail.get('VpcId'),
                        'SubnetMappings': firewall_detail.get('SubnetMappings', []),
                        'DeleteProtection': firewall_detail.get('DeleteProtection'),
                        'Description': firewall_detail.get('Description'),
                        'FirewallId': firewall_detail.get('FirewallId'),
                        'Tags': firewall_detail.get('Tags', {}),
                        'Status': firewall_status
                    }
                    firewalls.append(fw_info)
                except Exception as e:
                    logger.error(f"获取防火墙 {fw.get('FirewallName')} 详细信息失败: {str(e)}")
                    fw_info = {
                        'FirewallName': fw.get('FirewallName'),
                        'FirewallArn': fw.get('FirewallArn'),
                        'Description': fw.get('Description')
                    }
                    firewalls.append(fw_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.networkfirewall_client.list_firewalls(
                    NextToken=response['NextToken']
                )

                for fw in response.get('Firewalls', []):
                    try:
                        fw_detail = self.networkfirewall_client.describe_firewall(
                            FirewallName=fw.get('FirewallName'),
                            FirewallArn=fw.get('FirewallArn')
                        )
                        firewall_detail = fw_detail.get('Firewall', {})
                        firewall_status = fw_detail.get('FirewallStatus', {})
                        
                        fw_info = {
                            'FirewallName': firewall_detail.get('FirewallName'),
                            'FirewallArn': firewall_detail.get('FirewallArn'),
                            'FirewallPolicyArn': firewall_detail.get('FirewallPolicyArn'),
                            'VpcId': firewall_detail.get('VpcId'),
                            'SubnetMappings': firewall_detail.get('SubnetMappings', []),
                            'DeleteProtection': firewall_detail.get('DeleteProtection'),
                            'Description': firewall_detail.get('Description'),
                            'FirewallId': firewall_detail.get('FirewallId'),
                            'Tags': firewall_detail.get('Tags', {}),
                            'Status': firewall_status
                        }
                        firewalls.append(fw_info)
                    except Exception as e:
                        logger.error(f"获取防火墙 {fw.get('FirewallName')} 详细信息失败: {str(e)}")
                        fw_info = {
                            'FirewallName': fw.get('FirewallName'),
                            'FirewallArn': fw.get('FirewallArn'),
                            'Description': fw.get('Description')
                        }
                        firewalls.append(fw_info)

        except Exception as e:
            logger.error(f"获取Network Firewall信息失败: {str(e)}")

        return firewalls

    def get_global_accelerators(self) -> List[Dict[str, Any]]:
        """
        获取Global Accelerator信息

        Returns:
            List[Dict[str, Any]]: Global Accelerator列表
        """
        logger.info("获取Global Accelerator信息")
        accelerators = []

        try:
            # 获取所有Global Accelerator
            response = self.global_accelerator_client.list_accelerators()

            for acc in response.get('Accelerators', []):
                # 获取Accelerator的监听器
                listeners = []
                try:
                    listeners_response = self.global_accelerator_client.list_listeners(
                        AcceleratorArn=acc.get('AcceleratorArn')
                    )
                    
                    for listener in listeners_response.get('Listeners', []):
                        # 获取监听器的端点组
                        endpoint_groups = []
                        try:
                            eg_response = self.global_accelerator_client.list_endpoint_groups(
                                ListenerArn=listener.get('ListenerArn')
                            )
                            
                            endpoint_groups = eg_response.get('EndpointGroups', [])
                        except Exception as e:
                            logger.error(f"获取监听器 {listener.get('ListenerArn')} 的端点组失败: {str(e)}")
                        
                        listener_info = {
                            'ListenerArn': listener.get('ListenerArn'),
                            'PortRanges': listener.get('PortRanges', []),
                            'Protocol': listener.get('Protocol'),
                            'ClientAffinity': listener.get('ClientAffinity'),
                            'EndpointGroups': endpoint_groups
                        }
                        listeners.append(listener_info)
                        
                except Exception as e:
                    logger.error(f"获取Accelerator {acc.get('AcceleratorArn')} 的监听器失败: {str(e)}")

                acc_info = {
                    'AcceleratorArn': acc.get('AcceleratorArn'),
                    'Name': acc.get('Name'),
                    'IpAddressType': acc.get('IpAddressType'),
                    'Enabled': acc.get('Enabled'),
                    'Status': acc.get('Status'),
                    'IpSets': acc.get('IpSets', []),
                    'DnsName': acc.get('DnsName'),
                    'CreatedTime': acc.get('CreatedTime'),
                    'LastModifiedTime': acc.get('LastModifiedTime'),
                    'Listeners': listeners
                }
                accelerators.append(acc_info)

            # 处理分页
            while 'NextToken' in response:
                response = self.global_accelerator_client.list_accelerators(
                    NextToken=response['NextToken']
                )

                for acc in response.get('Accelerators', []):
                    # 获取Accelerator的监听器
                    listeners = []
                    try:
                        listeners_response = self.global_accelerator_client.list_listeners(
                            AcceleratorArn=acc.get('AcceleratorArn')
                        )
                        
                        for listener in listeners_response.get('Listeners', []):
                            # 获取监听器的端点组
                            endpoint_groups = []
                            try:
                                eg_response = self.global_accelerator_client.list_endpoint_groups(
                                    ListenerArn=listener.get('ListenerArn')
                                )
                                
                                endpoint_groups = eg_response.get('EndpointGroups', [])
                            except Exception as e:
                                logger.error(f"获取监听器 {listener.get('ListenerArn')} 的端点组失败: {str(e)}")
                            
                            listener_info = {
                                'ListenerArn': listener.get('ListenerArn'),
                                'PortRanges': listener.get('PortRanges', []),
                                'Protocol': listener.get('Protocol'),
                                'ClientAffinity': listener.get('ClientAffinity'),
                                'EndpointGroups': endpoint_groups
                            }
                            listeners.append(listener_info)
                            
                    except Exception as e:
                        logger.error(f"获取Accelerator {acc.get('AcceleratorArn')} 的监听器失败: {str(e)}")

                    acc_info = {
                        'AcceleratorArn': acc.get('AcceleratorArn'),
                        'Name': acc.get('Name'),
                        'IpAddressType': acc.get('IpAddressType'),
                        'Enabled': acc.get('Enabled'),
                        'Status': acc.get('Status'),
                        'IpSets': acc.get('IpSets', []),
                        'DnsName': acc.get('DnsName'),
                        'CreatedTime': acc.get('CreatedTime'),
                        'LastModifiedTime': acc.get('LastModifiedTime'),
                        'Listeners': listeners
                    }
                    accelerators.append(acc_info)

        except Exception as e:
            logger.error(f"获取Global Accelerator信息失败: {str(e)}")

        return accelerators

    def get_direct_connect_connections(self) -> List[Dict[str, Any]]:
        """
        获取Direct Connect连接信息

        Returns:
            List[Dict[str, Any]]: Direct Connect连接列表
        """
        logger.info("获取Direct Connect连接信息")
        connections = []

        try:
            # 获取所有Direct Connect连接
            response = self.directconnect_client.describe_connections()

            for conn in response.get('connections', []):
                conn_info = {
                    'connectionId': conn.get('connectionId'),
                    'connectionName': conn.get('connectionName'),
                    'connectionState': conn.get('connectionState'),
                    'region': conn.get('region'),
                    'location': conn.get('location'),
                    'bandwidth': conn.get('bandwidth'),
                    'vlan': conn.get('vlan'),
                    'partnerName': conn.get('partnerName'),
                    'loaIssueTime': conn.get('loaIssueTime'),
                    'lagId': conn.get('lagId'),
                    'awsDevice': conn.get('awsDevice'),
                    'jumboFrameCapable': conn.get('jumboFrameCapable'),
                    'awsDeviceV2': conn.get('awsDeviceV2'),
                    'hasLogicalRedundancy': conn.get('hasLogicalRedundancy'),
                    'tags': conn.get('tags', []),
                    'providerName': conn.get('providerName')
                }
                connections.append(conn_info)

        except Exception as e:
            logger.error(f"获取Direct Connect连接信息失败: {str(e)}")

        return connections

    def get_direct_connect_gateways(self) -> List[Dict[str, Any]]:
        """
        获取Direct Connect网关信息

        Returns:
            List[Dict[str, Any]]: Direct Connect网关列表
        """
        logger.info("获取Direct Connect网关信息")
        gateways = []

        try:
            # 获取所有Direct Connect网关
            response = self.directconnect_client.describe_direct_connect_gateways()

            for gw in response.get('directConnectGateways', []):
                # 获取Direct Connect网关的VPC关联
                vpc_associations = []
                try:
                    vpc_assoc_response = self.directconnect_client.describe_direct_connect_gateway_associations(
                        directConnectGatewayId=gw.get('directConnectGatewayId')
                    )
                    vpc_associations = vpc_assoc_response.get('directConnectGatewayAssociations', [])
                except Exception as e:
                    logger.error(f"获取Direct Connect网关 {gw.get('directConnectGatewayId')} 的VPC关联失败: {str(e)}")

                # 获取Direct Connect网关的虚拟接口关联
                virtual_interface_associations = []
                try:
                    vi_assoc_response = self.directconnect_client.describe_direct_connect_gateway_attachments(
                        directConnectGatewayId=gw.get('directConnectGatewayId')
                    )
                    virtual_interface_associations = vi_assoc_response.get('directConnectGatewayAttachments', [])
                except Exception as e:
                    logger.error(f"获取Direct Connect网关 {gw.get('directConnectGatewayId')} 的虚拟接口关联失败: {str(e)}")

                gw_info = {
                    'directConnectGatewayId': gw.get('directConnectGatewayId'),
                    'directConnectGatewayName': gw.get('directConnectGatewayName'),
                    'amazonSideAsn': gw.get('amazonSideAsn'),
                    'ownerAccount': gw.get('ownerAccount'),
                    'directConnectGatewayState': gw.get('directConnectGatewayState'),
                    'stateChangeError': gw.get('stateChangeError'),
                    'VpcAssociations': vpc_associations,
                    'VirtualInterfaceAssociations': virtual_interface_associations
                }
                gateways.append(gw_info)

            # 处理分页
            while 'nextToken' in response:
                response = self.directconnect_client.describe_direct_connect_gateways(
                    nextToken=response['nextToken']
                )

                for gw in response.get('directConnectGateways', []):
                    # 获取Direct Connect网关的VPC关联
                    vpc_associations = []
                    try:
                        vpc_assoc_response = self.directconnect_client.describe_direct_connect_gateway_associations(
                            directConnectGatewayId=gw.get('directConnectGatewayId')
                        )
                        vpc_associations = vpc_assoc_response.get('directConnectGatewayAssociations', [])
                    except Exception as e:
                        logger.error(f"获取Direct Connect网关 {gw.get('directConnectGatewayId')} 的VPC关联失败: {str(e)}")

                    # 获取Direct Connect网关的虚拟接口关联
                    virtual_interface_associations = []
                    try:
                        vi_assoc_response = self.directconnect_client.describe_direct_connect_gateway_attachments(
                            directConnectGatewayId=gw.get('directConnectGatewayId')
                        )
                        virtual_interface_associations = vi_assoc_response.get('directConnectGatewayAttachments', [])
                    except Exception as e:
                        logger.error(f"获取Direct Connect网关 {gw.get('directConnectGatewayId')} 的虚拟接口关联失败: {str(e)}")

                    gw_info = {
                        'directConnectGatewayId': gw.get('directConnectGatewayId'),
                        'directConnectGatewayName': gw.get('directConnectGatewayName'),
                        'amazonSideAsn': gw.get('amazonSideAsn'),
                        'ownerAccount': gw.get('ownerAccount'),
                        'directConnectGatewayState': gw.get('directConnectGatewayState'),
                        'stateChangeError': gw.get('stateChangeError'),
                        'VpcAssociations': vpc_associations,
                        'VirtualInterfaceAssociations': virtual_interface_associations
                    }
                    gateways.append(gw_info)

        except Exception as e:
            logger.error(f"获取Direct Connect网关信息失败: {str(e)}")

        return gateways

    def get_all_transit_gateway_assets(self) -> Dict[str, Dict[str, Any]]:
        """
        获取所有Transit Gateway及高级网络资源

        Returns:
            Dict[str, Dict[str, Any]]: 所有Transit Gateway及高级网络资源
        """
        transit_gateway_assets = {
            'transit_gateways': {tgw.get('TransitGatewayId'): tgw for tgw in self.get_transit_gateways()},
            'transit_gateway_attachments': {attachment.get('TransitGatewayAttachmentId'): attachment 
                                           for attachment in self.get_transit_gateway_attachments()},
            'transit_gateway_route_tables': {rt.get('TransitGatewayRouteTableId'): rt 
                                            for rt in self.get_transit_gateway_route_tables()},
            'network_firewalls': {fw.get('FirewallName'): fw for fw in self.get_network_firewalls()},
            'global_accelerators': {acc.get('AcceleratorArn'): acc for acc in self.get_global_accelerators()},
            'direct_connect_connections': {conn.get('connectionId'): conn 
                                          for conn in self.get_direct_connect_connections()},
            'direct_connect_gateways': {gw.get('directConnectGatewayId'): gw 
                                       for gw in self.get_direct_connect_gateways()},
        }

        return transit_gateway_assets