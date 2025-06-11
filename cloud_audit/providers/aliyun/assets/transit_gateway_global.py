"""阿里云传输网关及高级网络全局资源处理模块，负责获取云企业网(CEN)等全局网络资源信息。"""
import logging
import importlib.util
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class TransitGatewayGlobalAssetCollector:
    """阿里云传输网关及高级网络全局资源收集器"""

    def __init__(self, session):
        """
        初始化传输网关及高级网络全局资源收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        
        # 检查SDK可用性
        self.has_cbn_sdk = importlib.util.find_spec("aliyunsdkcbn") is not None
        self.has_expressconnect_sdk = importlib.util.find_spec("aliyunsdkexpressconnect") is not None
        self.has_smartag_sdk = importlib.util.find_spec("aliyunsdksmartag") is not None
        self.has_vpn_sdk = importlib.util.find_spec("aliyunsdkvpn") is not None
        
        # 初始化各个网络服务的客户端
        try:
            self.cen_client = session.get_client('cbn') if self.has_cbn_sdk else None  # 云企业网
        except Exception as e:
            logger.error(f"初始化云企业网客户端失败: {str(e)}")
            self.cen_client = None
            self.has_cbn_sdk = False
            
        try:
            self.express_connect_client = session.get_client('expressconnect') if self.has_expressconnect_sdk else None  # 高速通道
        except Exception as e:
            logger.error(f"初始化高速通道客户端失败: {str(e)}")
            self.express_connect_client = None
            self.has_expressconnect_sdk = False
            
        try:
            self.smartag_client = session.get_client('smartag') if self.has_smartag_sdk else None  # 智能接入网关
        except Exception as e:
            logger.error(f"初始化智能接入网关客户端失败: {str(e)}")
            self.smartag_client = None
            self.has_smartag_sdk = False
            
        try:
            self.vpn_client = session.get_client('vpn') if self.has_vpn_sdk else None  # VPN网关
        except Exception as e:
            logger.error(f"初始化VPN网关客户端失败: {str(e)}")
            self.vpn_client = None
            self.has_vpn_sdk = False
        
        # 打印SDK可用性信息
        logger.info(f"传输网关SDK可用性 - CBN:{self.has_cbn_sdk}, ExpressConnect:{self.has_expressconnect_sdk}, SmartAG:{self.has_smartag_sdk}, VPN:{self.has_vpn_sdk}")

    def get_cen_instances(self) -> List[Dict[str, Any]]:
        """
        获取云企业网(CEN)实例信息

        Returns:
            List[Dict[str, Any]]: 云企业网实例列表
        """
        logger.info("获取云企业网实例信息")
        instances = []

        if not self.has_cbn_sdk or not self.cen_client:
            logger.warning("缺少aliyunsdkcbn SDK，无法获取云企业网实例信息")
            return instances

        try:
            # 尝试正确的API操作名称
            api_actions = ['DescribeCens']  # 这是SDK中实际存在的API
            success = False
            
            for action in api_actions:
                try:
                    # 尝试使用当前API操作名称
                    request = self.session.create_request('cbn', action)
                    response = self.session.do_action_with_exception(request)
                    response_dict = self.session.parse_response(response)
                    
                    # 根据DescribeCens API的响应格式处理
                    cen_instances = response_dict.get('Cens', {}).get('Cen', [])
                    
                    if isinstance(cen_instances, list):
                        logger.info(f"成功使用 {action} API获取云企业网实例信息")
                        
                        # 统一处理实例数据
                        for instance in cen_instances:
                            instance_info = {
                                'CenId': instance.get('CenId'),
                                'Name': instance.get('Name'),
                                'Status': instance.get('Status'),
                                'Description': instance.get('Description', ''),
                                'ProtectionLevel': instance.get('ProtectionLevel', ''),
                                'CreationTime': instance.get('CreationTime', ''),
                                'Tags': instance.get('Tags', {}).get('Tag', []),
                            }
                            instances.append(instance_info)
                        
                        # 处理分页
                        page_number = 1
                        while response_dict.get('TotalCount', 0) > page_number * response_dict.get('PageSize', 0):
                            page_number += 1
                            request = self.session.create_request('cbn', action)
                            request.set_query_param('PageNumber', page_number)
                            response = self.session.do_action_with_exception(request)
                            response_dict = self.session.parse_response(response)
                            
                            # 再次处理响应
                            cen_instances = response_dict.get('Cens', {}).get('Cen', [])
                            
                            for instance in cen_instances:
                                instance_info = {
                                    'CenId': instance.get('CenId'),
                                    'Name': instance.get('Name'),
                                    'Status': instance.get('Status'),
                                    'Description': instance.get('Description', ''),
                                    'ProtectionLevel': instance.get('ProtectionLevel', ''),
                                    'CreationTime': instance.get('CreationTime', ''),
                                    'Tags': instance.get('Tags', {}).get('Tag', []),
                                }
                                instances.append(instance_info)
                        
                        success = True
                        break
                    
                except Exception as e:
                    logger.debug(f"尝试使用 {action} API获取云企业网实例信息失败: {str(e)}")
                    continue
            
            if not success:
                logger.error("所有尝试的API操作名称都失败，无法获取云企业网实例信息")
                
        except Exception as e:
            logger.error(f"获取云企业网实例信息失败: {str(e)}")

        return instances

    def get_cen_attachments(self, cen_id: str) -> List[Dict[str, Any]]:
        """
        获取云企业网实例的网络实例连接

        Args:
            cen_id: 云企业网实例ID

        Returns:
            List[Dict[str, Any]]: 网络实例连接列表
        """
        logger.info(f"获取云企业网实例 {cen_id} 的网络实例连接")
        attachments = []

        if not self.has_cbn_sdk or not self.cen_client:
            logger.warning("缺少aliyunsdkcbn SDK，无法获取云企业网实例的网络实例连接")
            return attachments

        try:
            # 使用正确的API操作名称
            api_actions = ['DescribeCenAttachedChildInstances']  # 这是SDK中实际存在的API
            success = False
            
            for action in api_actions:
                try:
                    # 尝试使用当前API操作名称
                    request = self.session.create_request('cbn', action)
                    request.set_query_param('CenId', cen_id)
                    response = self.session.do_action_with_exception(request)
                    response_dict = self.session.parse_response(response)
                    
                    # 根据DescribeCenAttachedChildInstances API的响应格式处理
                    attachment_list = response_dict.get('ChildInstances', {}).get('ChildInstance', [])
                    
                    if isinstance(attachment_list, list):
                        logger.info(f"成功使用 {action} API获取云企业网实例 {cen_id} 的网络实例连接")
                        
                        # 统一处理附件数据
                        for attachment in attachment_list:
                            attachment_info = {
                                'CenId': cen_id,
                                'ChildInstanceId': attachment.get('ChildInstanceId'),
                                'ChildInstanceType': attachment.get('ChildInstanceType'),
                                'ChildInstanceRegionId': attachment.get('ChildInstanceRegionId'),
                                'ChildInstanceOwnerId': attachment.get('ChildInstanceOwnerId'),
                                'Status': attachment.get('Status'),
                            }
                            attachments.append(attachment_info)
                        
                        # 处理分页
                        page_number = 1
                        while response_dict.get('TotalCount', 0) > page_number * response_dict.get('PageSize', 0):
                            page_number += 1
                            request = self.session.create_request('cbn', action)
                            request.set_query_param('CenId', cen_id)
                            request.set_query_param('PageNumber', page_number)
                            response = self.session.do_action_with_exception(request)
                            response_dict = self.session.parse_response(response)
                            
                            # 再次处理响应
                            attachment_list = response_dict.get('ChildInstances', {}).get('ChildInstance', [])
                            
                            for attachment in attachment_list:
                                attachment_info = {
                                    'CenId': cen_id,
                                    'ChildInstanceId': attachment.get('ChildInstanceId'),
                                    'ChildInstanceType': attachment.get('ChildInstanceType'),
                                    'ChildInstanceRegionId': attachment.get('ChildInstanceRegionId'),
                                    'ChildInstanceOwnerId': attachment.get('ChildInstanceOwnerId'),
                                    'Status': attachment.get('Status'),
                                }
                                attachments.append(attachment_info)
                        
                        success = True
                        break
                
                except Exception as e:
                    logger.debug(f"尝试使用 {action} API获取云企业网实例 {cen_id} 的网络实例连接失败: {str(e)}")
                    continue
            
            if not success:
                logger.error(f"所有尝试的API操作名称都失败，无法获取云企业网实例 {cen_id} 的网络实例连接")
                
        except Exception as e:
            logger.error(f"获取云企业网实例 {cen_id} 的网络实例连接失败: {str(e)}")

        return attachments

    def get_express_connect_physical_connections(self) -> List[Dict[str, Any]]:
        """
        获取高速通道物理专线信息

        Returns:
            List[Dict[str, Any]]: 物理专线列表
        """
        logger.info("获取高速通道物理专线信息")
        connections = []
        
        # 检查SDK是否可用
        if not self.has_expressconnect_sdk:
            logger.warning("缺少aliyunsdkexpressconnect SDK，无法获取高速通道物理专线信息")
            return connections

        try:
            # 获取所有物理专线
            request = self.session.create_request('expressconnect', 'DescribePhysicalConnections')
            response = self.session.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)

            for connection in response_dict.get('PhysicalConnectionSet', {}).get('PhysicalConnectionType', []):
                connection_info = {
                    'PhysicalConnectionId': connection.get('PhysicalConnectionId'),
                    'AccessPointId': connection.get('AccessPointId'),
                    'Type': connection.get('Type'),
                    'Status': connection.get('Status'),
                    'BusinessStatus': connection.get('BusinessStatus'),
                    'CreationTime': connection.get('CreationTime'),
                    'EnabledTime': connection.get('EnabledTime'),
                    'LineOperator': connection.get('LineOperator'),
                    'Spec': connection.get('Spec'),
                    'PeerLocation': connection.get('PeerLocation'),
                    'PortType': connection.get('PortType'),
                    'RedundantPhysicalConnectionId': connection.get('RedundantPhysicalConnectionId'),
                    'Name': connection.get('Name'),
                    'Description': connection.get('Description'),
                    'AdLocation': connection.get('AdLocation'),
                    'PortNumber': connection.get('PortNumber'),
                    'CircuitCode': connection.get('CircuitCode'),
                    'Bandwidth': connection.get('Bandwidth'),
                }
                connections.append(connection_info)

            # 处理分页
            page_number = 1
            while response_dict.get('TotalCount', 0) > page_number * response_dict.get('PageSize', 0):
                page_number += 1
                request = self.session.create_request('expressconnect', 'DescribePhysicalConnections')
                request.set_query_param('PageNumber', page_number)
                response = self.session.do_action_with_exception(request)
                response_dict = self.session.parse_response(response)

                for connection in response_dict.get('PhysicalConnectionSet', {}).get('PhysicalConnectionType', []):
                    connection_info = {
                        'PhysicalConnectionId': connection.get('PhysicalConnectionId'),
                        'AccessPointId': connection.get('AccessPointId'),
                        'Type': connection.get('Type'),
                        'Status': connection.get('Status'),
                        'BusinessStatus': connection.get('BusinessStatus'),
                        'CreationTime': connection.get('CreationTime'),
                        'EnabledTime': connection.get('EnabledTime'),
                        'LineOperator': connection.get('LineOperator'),
                        'Spec': connection.get('Spec'),
                        'PeerLocation': connection.get('PeerLocation'),
                        'PortType': connection.get('PortType'),
                        'RedundantPhysicalConnectionId': connection.get('RedundantPhysicalConnectionId'),
                        'Name': connection.get('Name'),
                        'Description': connection.get('Description'),
                        'AdLocation': connection.get('AdLocation'),
                        'PortNumber': connection.get('PortNumber'),
                        'CircuitCode': connection.get('CircuitCode'),
                        'Bandwidth': connection.get('Bandwidth'),
                    }
                    connections.append(connection_info)

        except Exception as e:
            logger.error(f"获取高速通道物理专线信息失败: {str(e)}")

        return connections

    def get_vpn_gateways(self) -> List[Dict[str, Any]]:
        """
        获取VPN网关信息

        Returns:
            List[Dict[str, Any]]: VPN网关列表
        """
        logger.info("获取VPN网关信息")
        gateways = []
        
        # 检查SDK是否可用
        if not self.has_vpn_sdk:
            logger.warning("缺少aliyunsdkvpn SDK，无法获取VPN网关信息")
            return gateways

        try:
            # 获取所有VPN网关
            request = self.session.create_request('vpn', 'DescribeVpnGateways')
            response = self.session.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)

            for gateway in response_dict.get('VpnGateways', {}).get('VpnGateway', []):
                gateway_info = {
                    'VpnGatewayId': gateway.get('VpnGatewayId'),
                    'VpcId': gateway.get('VpcId'),
                    'VSwitchId': gateway.get('VSwitchId'),
                    'InternetIp': gateway.get('InternetIp'),
                    'CreateTime': gateway.get('CreateTime'),
                    'EndTime': gateway.get('EndTime'),
                    'Spec': gateway.get('Spec'),
                    'Name': gateway.get('Name'),
                    'Description': gateway.get('Description'),
                    'Status': gateway.get('Status'),
                    'BusinessStatus': gateway.get('BusinessStatus'),
                    'ChargeType': gateway.get('ChargeType'),
                    'IpsecVpn': gateway.get('IpsecVpn'),
                    'SslVpn': gateway.get('SslVpn'),
                    'SslMaxConnections': gateway.get('SslMaxConnections'),
                    'Tag': gateway.get('Tag'),
                }
                gateways.append(gateway_info)

            # 处理分页
            page_number = 1
            while response_dict.get('TotalCount', 0) > page_number * response_dict.get('PageSize', 0):
                page_number += 1
                request = self.session.create_request('vpn', 'DescribeVpnGateways')
                request.set_query_param('PageNumber', page_number)
                response = self.session.do_action_with_exception(request)
                response_dict = self.session.parse_response(response)

                for gateway in response_dict.get('VpnGateways', {}).get('VpnGateway', []):
                    gateway_info = {
                        'VpnGatewayId': gateway.get('VpnGatewayId'),
                        'VpcId': gateway.get('VpcId'),
                        'VSwitchId': gateway.get('VSwitchId'),
                        'InternetIp': gateway.get('InternetIp'),
                        'CreateTime': gateway.get('CreateTime'),
                        'EndTime': gateway.get('EndTime'),
                        'Spec': gateway.get('Spec'),
                        'Name': gateway.get('Name'),
                        'Description': gateway.get('Description'),
                        'Status': gateway.get('Status'),
                        'BusinessStatus': gateway.get('BusinessStatus'),
                        'ChargeType': gateway.get('ChargeType'),
                        'IpsecVpn': gateway.get('IpsecVpn'),
                        'SslVpn': gateway.get('SslVpn'),
                        'SslMaxConnections': gateway.get('SslMaxConnections'),
                        'Tag': gateway.get('Tag'),
                    }
                    gateways.append(gateway_info)

        except Exception as e:
            logger.error(f"获取VPN网关信息失败: {str(e)}")

        return gateways

    def get_all_transit_gateway_global_assets(self) -> Dict[str, Any]:
        """
        获取所有传输网关及高级网络全局资产信息（主要是云企业网 CEN）

        Returns:
            Dict[str, Any]: 所有传输网关及高级网络全局资产信息
        """
        logger.info("获取所有传输网关及高级网络全局资产信息")
        
        # 检查SDK可用性状态
        sdk_status = {
            'cbn': 'available' if self.has_cbn_sdk else 'sdk_missing',
        }
        
        # 获取全局网络资源（主要是CEN）
        cen_instances = self.get_cen_instances() if self.has_cbn_sdk else []
        
        # 获取云企业网实例的网络实例连接（这些连接信息在CEN级别是全局可见的）
        cen_attachments = {}
        for instance in cen_instances:
            cen_id = instance.get('CenId')
            if cen_id:
                cen_attachments[cen_id] = self.get_cen_attachments(cen_id)
        
        # 整合所有传输网关及高级网络全局资产信息
        transit_gateway_assets = {
            'sdk_status': sdk_status,
            'cen_instances': {instance['CenId']: instance for instance in cen_instances},
            'cen_attachments': cen_attachments,
            # 注意：以下资源移到区域收集器中，因为它们是区域相关的
            # 'physical_connections': {},  # 高速通道物理专线是区域相关的
            # 'vpn_gateways': {},  # VPN网关是区域相关的
        }
        
        # 记录摘要信息
        logger.info(f"已获取 {len(cen_instances)} 个云企业网实例（全局资源）")
        logger.info("区域相关的高速通道和VPN网关资源请从区域收集器获取")
        
        return transit_gateway_assets