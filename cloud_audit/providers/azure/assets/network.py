"""Azure网络资源收集器"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class NetworkAssetCollector:
    """Azure网络资源收集器"""
    
    def __init__(self, session):
        """
        初始化网络资源收集器
        
        Args:
            session: Azure会话对象
        """
        self.session = session
        self.network_client = session.get_client('network')
    
    def get_virtual_networks(self) -> Dict[str, Any]:
        """
        获取虚拟网络列表
        
        Returns:
            Dict[str, Any]: 虚拟网络信息字典，键为虚拟网络ID
        """
        try:
            vnets = {}
            for vnet in self.network_client.virtual_networks.list_all():
                vnet_dict = {
                    'id': vnet.id,
                    'name': vnet.name,
                    'location': vnet.location,
                    'resource_group': vnet.id.split('/')[4] if vnet.id else None,
                    'address_space': vnet.address_space.address_prefixes if vnet.address_space else [],
                    'subnets': [],
                    'dns_servers': vnet.dhcp_options.dns_servers if vnet.dhcp_options else [],
                    'provisioning_state': vnet.provisioning_state,
                    'tags': dict(vnet.tags) if vnet.tags else {}
                }
                
                # 获取子网信息
                if vnet.subnets:
                    for subnet in vnet.subnets:
                        subnet_dict = {
                            'id': subnet.id,
                            'name': subnet.name,
                            'address_prefix': subnet.address_prefix,
                            'provisioning_state': subnet.provisioning_state,
                            'network_security_group': subnet.network_security_group.id if subnet.network_security_group else None,
                            'route_table': subnet.route_table.id if subnet.route_table else None
                        }
                        vnet_dict['subnets'].append(subnet_dict)
                
                vnets[vnet.id] = vnet_dict
            
            logger.info(f"获取到 {len(vnets)} 个虚拟网络")
            return vnets
            
        except Exception as e:
            logger.error(f"获取虚拟网络列表失败: {str(e)}")
            return {}
    
    def get_network_security_groups(self) -> Dict[str, Any]:
        """
        获取网络安全组列表
        
        Returns:
            Dict[str, Any]: 网络安全组信息字典，键为网络安全组ID
        """
        try:
            nsgs = {}
            for nsg in self.network_client.network_security_groups.list_all():
                nsg_dict = {
                    'id': nsg.id,
                    'name': nsg.name,
                    'location': nsg.location,
                    'resource_group': nsg.id.split('/')[4] if nsg.id else None,
                    'security_rules': [],
                    'default_security_rules': [],
                    'network_interfaces': [nic.id for nic in nsg.network_interfaces] if nsg.network_interfaces else [],
                    'subnets': [subnet.id for subnet in nsg.subnets] if nsg.subnets else [],
                    'provisioning_state': nsg.provisioning_state,
                    'tags': dict(nsg.tags) if nsg.tags else {}
                }
                
                # 获取安全规则
                if nsg.security_rules:
                    for rule in nsg.security_rules:
                        rule_dict = {
                            'name': rule.name,
                            'protocol': rule.protocol,
                            'source_port_range': rule.source_port_range,
                            'destination_port_range': rule.destination_port_range,
                            'source_address_prefix': rule.source_address_prefix,
                            'destination_address_prefix': rule.destination_address_prefix,
                            'access': rule.access,
                            'priority': rule.priority,
                            'direction': rule.direction
                        }
                        nsg_dict['security_rules'].append(rule_dict)
                
                # 获取默认安全规则
                if nsg.default_security_rules:
                    for rule in nsg.default_security_rules:
                        rule_dict = {
                            'name': rule.name,
                            'protocol': rule.protocol,
                            'source_port_range': rule.source_port_range,
                            'destination_port_range': rule.destination_port_range,
                            'source_address_prefix': rule.source_address_prefix,
                            'destination_address_prefix': rule.destination_address_prefix,
                            'access': rule.access,
                            'priority': rule.priority,
                            'direction': rule.direction
                        }
                        nsg_dict['default_security_rules'].append(rule_dict)
                
                nsgs[nsg.id] = nsg_dict
            
            logger.info(f"获取到 {len(nsgs)} 个网络安全组")
            return nsgs
            
        except Exception as e:
            logger.error(f"获取网络安全组列表失败: {str(e)}")
            return {}
    
    def get_public_ip_addresses(self) -> Dict[str, Any]:
        """
        获取公共IP地址列表
        
        Returns:
            Dict[str, Any]: 公共IP地址信息字典，键为公共IP地址ID
        """
        try:
            public_ips = {}
            for pip in self.network_client.public_ip_addresses.list_all():
                pip_dict = {
                    'id': pip.id,
                    'name': pip.name,
                    'location': pip.location,
                    'resource_group': pip.id.split('/')[4] if pip.id else None,
                    'ip_address': pip.ip_address,
                    'public_ip_allocation_method': pip.public_ip_allocation_method,
                    'public_ip_address_version': pip.public_ip_address_version,
                    'dns_settings': {
                        'domain_name_label': pip.dns_settings.domain_name_label,
                        'fqdn': pip.dns_settings.fqdn
                    } if pip.dns_settings else None,
                    'idle_timeout_in_minutes': pip.idle_timeout_in_minutes,
                    'provisioning_state': pip.provisioning_state,
                    'sku': pip.sku.name if pip.sku else None,
                    'tags': dict(pip.tags) if pip.tags else {}
                }
                public_ips[pip.id] = pip_dict
            
            logger.info(f"获取到 {len(public_ips)} 个公共IP地址")
            return public_ips
            
        except Exception as e:
            logger.error(f"获取公共IP地址列表失败: {str(e)}")
            return {}
    
    def get_network_interfaces(self) -> Dict[str, Any]:
        """
        获取网络接口列表
        
        Returns:
            Dict[str, Any]: 网络接口信息字典，键为网络接口ID
        """
        try:
            nics = {}
            for nic in self.network_client.network_interfaces.list_all():
                nic_dict = {
                    'id': nic.id,
                    'name': nic.name,
                    'location': nic.location,
                    'resource_group': nic.id.split('/')[4] if nic.id else None,
                    'mac_address': nic.mac_address,
                    'primary': nic.primary,
                    'enable_accelerated_networking': nic.enable_accelerated_networking,
                    'enable_ip_forwarding': nic.enable_ip_forwarding,
                    'network_security_group': nic.network_security_group.id if nic.network_security_group else None,
                    'virtual_machine': nic.virtual_machine.id if nic.virtual_machine else None,
                    'ip_configurations': [],
                    'provisioning_state': nic.provisioning_state,
                    'tags': dict(nic.tags) if nic.tags else {}
                }
                
                # 获取IP配置
                if nic.ip_configurations:
                    for ip_config in nic.ip_configurations:
                        ip_config_dict = {
                            'name': ip_config.name,
                            'private_ip_address': ip_config.private_ip_address,
                            'private_ip_allocation_method': ip_config.private_ip_allocation_method,
                            'public_ip_address': ip_config.public_ip_address.id if ip_config.public_ip_address else None,
                            'subnet': ip_config.subnet.id if ip_config.subnet else None,
                            'primary': ip_config.primary
                        }
                        nic_dict['ip_configurations'].append(ip_config_dict)
                
                nics[nic.id] = nic_dict
            
            logger.info(f"获取到 {len(nics)} 个网络接口")
            return nics
            
        except Exception as e:
            logger.error(f"获取网络接口列表失败: {str(e)}")
            return {}
    
    def get_load_balancers(self) -> Dict[str, Any]:
        """
        获取负载均衡器列表
        
        Returns:
            Dict[str, Any]: 负载均衡器信息字典，键为负载均衡器ID
        """
        try:
            load_balancers = {}
            for lb in self.network_client.load_balancers.list_all():
                lb_dict = {
                    'id': lb.id,
                    'name': lb.name,
                    'location': lb.location,
                    'resource_group': lb.id.split('/')[4] if lb.id else None,
                    'sku': lb.sku.name if lb.sku else None,
                    'frontend_ip_configurations': [],
                    'backend_address_pools': [],
                    'load_balancing_rules': [],
                    'probes': [],
                    'inbound_nat_rules': [],
                    'provisioning_state': lb.provisioning_state,
                    'tags': dict(lb.tags) if lb.tags else {}
                }
                
                # 获取前端IP配置
                if lb.frontend_ip_configurations:
                    for frontend in lb.frontend_ip_configurations:
                        frontend_dict = {
                            'name': frontend.name,
                            'private_ip_address': frontend.private_ip_address,
                            'private_ip_allocation_method': frontend.private_ip_allocation_method,
                            'public_ip_address': frontend.public_ip_address.id if frontend.public_ip_address else None,
                            'subnet': frontend.subnet.id if frontend.subnet else None
                        }
                        lb_dict['frontend_ip_configurations'].append(frontend_dict)
                
                # 获取后端地址池
                if lb.backend_address_pools:
                    for backend in lb.backend_address_pools:
                        backend_dict = {
                            'name': backend.name,
                            'backend_ip_configurations': [ip.id for ip in backend.backend_ip_configurations] if backend.backend_ip_configurations else []
                        }
                        lb_dict['backend_address_pools'].append(backend_dict)
                
                load_balancers[lb.id] = lb_dict
            
            logger.info(f"获取到 {len(load_balancers)} 个负载均衡器")
            return load_balancers
            
        except Exception as e:
            logger.error(f"获取负载均衡器列表失败: {str(e)}")
            return {}
    
    def get_application_gateways(self) -> Dict[str, Any]:
        """
        获取应用程序网关列表
        
        Returns:
            Dict[str, Any]: 应用程序网关信息字典，键为应用程序网关ID
        """
        try:
            app_gateways = {}
            for agw in self.network_client.application_gateways.list_all():
                agw_dict = {
                    'id': agw.id,
                    'name': agw.name,
                    'location': agw.location,
                    'resource_group': agw.id.split('/')[4] if agw.id else None,
                    'sku': {
                        'name': agw.sku.name,
                        'tier': agw.sku.tier,
                        'capacity': agw.sku.capacity
                    } if agw.sku else None,
                    'operational_state': agw.operational_state,
                    'provisioning_state': agw.provisioning_state,
                    'gateway_ip_configurations': len(agw.gateway_ip_configurations) if agw.gateway_ip_configurations else 0,
                    'frontend_ip_configurations': len(agw.frontend_ip_configurations) if agw.frontend_ip_configurations else 0,
                    'backend_address_pools': len(agw.backend_address_pools) if agw.backend_address_pools else 0,
                    'http_listeners': len(agw.http_listeners) if agw.http_listeners else 0,
                    'request_routing_rules': len(agw.request_routing_rules) if agw.request_routing_rules else 0,
                    'tags': dict(agw.tags) if agw.tags else {}
                }
                app_gateways[agw.id] = agw_dict
            
            logger.info(f"获取到 {len(app_gateways)} 个应用程序网关")
            return app_gateways
            
        except Exception as e:
            logger.error(f"获取应用程序网关列表失败: {str(e)}")
            return {}
    
    def get_all_network_assets(self) -> Dict[str, Any]:
        """
        获取所有网络资源
        
        Returns:
            Dict[str, Any]: 所有网络资源信息
        """
        logger.info("开始收集Azure网络资源")
        
        network_assets = {
            'virtual_networks': self.get_virtual_networks(),
            'network_security_groups': self.get_network_security_groups(),
            'public_ip_addresses': self.get_public_ip_addresses(),
            'network_interfaces': self.get_network_interfaces(),
            'load_balancers': self.get_load_balancers(),
            'application_gateways': self.get_application_gateways()
        }
        
        # 统计信息
        total_count = sum(len(assets) for assets in network_assets.values())
        logger.info(f"Azure网络资源收集完成，共 {total_count} 个资源")
        
        return network_assets 