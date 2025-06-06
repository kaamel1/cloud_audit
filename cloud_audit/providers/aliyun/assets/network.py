"""阿里云网络资源处理模块，负责获取VPC、安全组等网络资源信息。"""
import logging
import json
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class NetworkAssetCollector:
    """阿里云网络资源收集器"""

    def __init__(self, session):
        """
        初始化网络资源收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        self.vpc_client = session.get_client('vpc')
        self.ecs_client = session.get_client('ecs')  # 用于获取安全组信息

    def get_vpcs(self) -> List[Dict[str, Any]]:
        """
        获取VPC信息

        Returns:
            List[Dict[str, Any]]: VPC列表
        """
        logger.info("获取VPC信息")
        vpcs = []

        try:
            # 导入阿里云VPC SDK请求模块
            try:
                from aliyunsdkvpc.request.v20160428 import DescribeVpcsRequest
            except ImportError:
                logger.warning(
                    "阿里云VPC SDK未安装，跳过VPC信息收集。\n"
                    "如需收集VPC数据，请安装：pip install aliyun-python-sdk-vpc"
                )
                return vpcs
            
            # 创建请求对象
            request = DescribeVpcsRequest.DescribeVpcsRequest()
            request.set_accept_format('json')
            
            # 设置分页参数
            page_size = 50
            request.set_PageSize(page_size)
            
            # 分页获取所有VPC
            page_number = 1
            total_vpcs = []
            
            while True:
                request.set_PageNumber(page_number)
                response = self.vpc_client.do_action_with_exception(request)
                response_json = json.loads(response)
                
                current_vpcs = response_json.get('Vpcs', {}).get('Vpc', [])
                total_vpcs.extend(current_vpcs)
                
                # 判断是否还有更多页
                total_count = response_json.get('TotalCount', 0)
                if page_number * page_size >= total_count:
                    break
                    
                page_number += 1
            
            # 处理VPC数据
            for vpc in total_vpcs:
                vpc_info = {
                    'VpcId': vpc.get('VpcId'),
                    'VpcName': vpc.get('VpcName'),
                    'CidrBlock': vpc.get('CidrBlock'),
                    'Status': vpc.get('Status'),
                    'CreationTime': vpc.get('CreationTime'),
                    'RegionId': vpc.get('RegionId'),
                    'IsDefault': vpc.get('IsDefault'),
                    'Description': vpc.get('Description'),
                }
                vpcs.append(vpc_info)
                
        except Exception as e:
            logger.error(f"获取VPC信息失败: {str(e)}")
        
        return vpcs

    def get_vswitches(self) -> List[Dict[str, Any]]:
        """
        获取交换机信息

        Returns:
            List[Dict[str, Any]]: 交换机列表
        """
        logger.info("获取交换机信息")
        vswitches = []

        try:
            # 导入阿里云VPC SDK请求模块
            try:
                from aliyunsdkvpc.request.v20160428 import DescribeVSwitchesRequest
            except ImportError:
                logger.warning(
                    "阿里云VPC SDK未安装，跳过交换机信息收集。\n"
                    "如需收集交换机数据，请安装：pip install aliyun-python-sdk-vpc"
                )
                return vswitches
            
            # 创建请求对象
            request = DescribeVSwitchesRequest.DescribeVSwitchesRequest()
            request.set_accept_format('json')
            
            # 设置分页参数
            page_size = 50
            request.set_PageSize(page_size)
            
            # 分页获取所有交换机
            page_number = 1
            total_vswitches = []
            
            while True:
                request.set_PageNumber(page_number)
                response = self.vpc_client.do_action_with_exception(request)
                response_json = json.loads(response)
                
                current_vswitches = response_json.get('VSwitches', {}).get('VSwitch', [])
                total_vswitches.extend(current_vswitches)
                
                # 判断是否还有更多页
                total_count = response_json.get('TotalCount', 0)
                if page_number * page_size >= total_count:
                    break
                    
                page_number += 1
            
            # 处理交换机数据
            for vswitch in total_vswitches:
                vswitch_info = {
                    'VSwitchId': vswitch.get('VSwitchId'),
                    'VSwitchName': vswitch.get('VSwitchName'),
                    'VpcId': vswitch.get('VpcId'),
                    'CidrBlock': vswitch.get('CidrBlock'),
                    'Status': vswitch.get('Status'),
                    'ZoneId': vswitch.get('ZoneId'),
                    'CreationTime': vswitch.get('CreationTime'),
                    'IsDefault': vswitch.get('IsDefault'),
                    'Description': vswitch.get('Description'),
                }
                vswitches.append(vswitch_info)
                
        except Exception as e:
            logger.error(f"获取交换机信息失败: {str(e)}")
        
        return vswitches

    def get_security_groups(self) -> List[Dict[str, Any]]:
        """
        获取安全组信息

        Returns:
            List[Dict[str, Any]]: 安全组列表
        """
        logger.info("获取安全组信息")
        security_groups = []

        try:
            # 导入阿里云ECS SDK请求模块（安全组在ECS SDK中）
            from aliyunsdkecs.request.v20140526 import DescribeSecurityGroupsRequest
            from aliyunsdkecs.request.v20140526 import DescribeSecurityGroupAttributeRequest
            
            # 创建请求对象
            request = DescribeSecurityGroupsRequest.DescribeSecurityGroupsRequest()
            request.set_accept_format('json')
            
            # 设置分页参数
            page_size = 50
            request.set_PageSize(page_size)
            
            # 分页获取所有安全组
            page_number = 1
            total_sgs = []
            
            while True:
                request.set_PageNumber(page_number)
                response = self.ecs_client.do_action_with_exception(request)
                response_json = json.loads(response)
                
                current_sgs = response_json.get('SecurityGroups', {}).get('SecurityGroup', [])
                total_sgs.extend(current_sgs)
                
                # 判断是否还有更多页
                total_count = response_json.get('TotalCount', 0)
                if page_number * page_size >= total_count:
                    break
                    
                page_number += 1
            
            # 处理安全组数据，并获取详细规则
            for sg in total_sgs:
                sg_id = sg.get('SecurityGroupId')
                
                # 获取安全组详细规则
                sg_detail_request = DescribeSecurityGroupAttributeRequest.DescribeSecurityGroupAttributeRequest()
                sg_detail_request.set_accept_format('json')
                sg_detail_request.set_SecurityGroupId(sg_id)
                
                sg_detail_response = self.ecs_client.do_action_with_exception(sg_detail_request)
                sg_detail = json.loads(sg_detail_response)
                
                sg_info = {
                    'SecurityGroupId': sg_id,
                    'SecurityGroupName': sg.get('SecurityGroupName'),
                    'Description': sg.get('Description'),
                    'VpcId': sg.get('VpcId'),
                    'CreationTime': sg.get('CreationTime'),
                    'IngressRules': sg_detail.get('Permissions', {}).get('Permission', []),
                    'Tags': sg.get('Tags', {}).get('Tag', []),
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
            # 导入阿里云VPC SDK请求模块
            try:
                from aliyunsdkvpc.request.v20160428 import DescribeRouteTablesRequest, DescribeVpcsRequest
            except ImportError:
                logger.warning(
                    "阿里云VPC SDK未安装，跳过路由表信息收集。\n"
                    "如需收集路由表数据，请安装：pip install aliyun-python-sdk-vpc"
                )
                return route_tables
            
            # 首先获取所有VPC，因为DescribeRouteTables需要至少一个参数（VRouterId或RouteTableId等）
            # 我们通过VPC来查询每个VPC下的路由表
            vpcs_request = DescribeVpcsRequest.DescribeVpcsRequest()
            vpcs_request.set_accept_format('json')
            vpcs_request.set_PageSize(50)
            
            all_vpcs = []
            page_number = 1
            
            # 获取所有VPC
            while True:
                vpcs_request.set_PageNumber(page_number)
                response = self.vpc_client.do_action_with_exception(vpcs_request)
                response_json = json.loads(response)
                
                current_vpcs = response_json.get('Vpcs', {}).get('Vpc', [])
                all_vpcs.extend(current_vpcs)
                
                total_count = response_json.get('TotalCount', 0)
                if page_number * 50 >= total_count:
                    break
                    
                page_number += 1
            
            # 为每个VPC查询路由表
            for vpc in all_vpcs:
                vpc_id = vpc.get('VpcId')
                vrouter_id = vpc.get('VRouterId')  # VPC的路由器ID
                
                if not vrouter_id:
                    continue
                    
                # 创建路由表查询请求，使用VRouterId参数
                request = DescribeRouteTablesRequest.DescribeRouteTablesRequest()
                request.set_accept_format('json')
                request.set_VRouterId(vrouter_id)  # 传递必需的VRouterId参数
                request.set_PageSize(50)
                
                # 分页获取该VPC的所有路由表
                page_number = 1
                
                while True:
                    request.set_PageNumber(page_number)
                    response = self.vpc_client.do_action_with_exception(request)
                    response_json = json.loads(response)
                    
                    current_rts = response_json.get('RouteTables', {}).get('RouteTable', [])
                    
                    # 处理路由表数据
                    for rt in current_rts:
                        rt_info = {
                            'RouteTableId': rt.get('RouteTableId'),
                            'RouteTableType': rt.get('RouteTableType'),
                            'VpcId': rt.get('VpcId'),
                            'VRouterId': rt.get('VRouterId'),
                            'CreationTime': rt.get('CreationTime'),
                            'ResourceGroupId': rt.get('ResourceGroupId'),
                            'RouteEntrys': rt.get('RouteEntrys', {}).get('RouteEntry', []),
                        }
                        route_tables.append(rt_info)
                    
                    # 判断是否还有更多页
                    total_count = response_json.get('TotalCount', 0)
                    if page_number * 50 >= total_count:
                        break
                        
                    page_number += 1
                
        except Exception as e:
            logger.error(f"获取路由表信息失败: {str(e)}")
        
        return route_tables

    def get_network_acls(self) -> List[Dict[str, Any]]:
        """
        获取网络ACL信息

        Returns:
            List[Dict[str, Any]]: 网络ACL列表
        """
        logger.info("获取网络ACL信息")
        network_acls = []

        try:
            # 导入阿里云VPC SDK请求模块
            try:
                from aliyunsdkvpc.request.v20160428 import DescribeNetworkAclsRequest
            except ImportError:
                logger.warning(
                    "阿里云VPC SDK未安装，跳过网络ACL信息收集。\n"
                    "如需收集网络ACL数据，请安装：pip install aliyun-python-sdk-vpc"
                )
                return network_acls
            
            # 创建请求对象
            request = DescribeNetworkAclsRequest.DescribeNetworkAclsRequest()
            request.set_accept_format('json')
            
            # 设置分页参数
            page_size = 50
            request.set_PageSize(page_size)
            
            # 分页获取所有网络ACL
            page_number = 1
            total_acls = []
            
            while True:
                request.set_PageNumber(page_number)
                response = self.vpc_client.do_action_with_exception(request)
                response_json = json.loads(response)
                
                current_acls = response_json.get('NetworkAcls', {}).get('NetworkAcl', [])
                total_acls.extend(current_acls)
                
                # 判断是否还有更多页
                total_count = response_json.get('TotalCount', 0)
                if page_number * page_size >= total_count:
                    break
                    
                page_number += 1
            
            # 处理网络ACL数据
            for acl in total_acls:
                acl_info = {
                    'NetworkAclId': acl.get('NetworkAclId'),
                    'NetworkAclName': acl.get('NetworkAclName'),
                    'VpcId': acl.get('VpcId'),
                    'Status': acl.get('Status'),
                    'Description': acl.get('Description'),
                    'CreationTime': acl.get('CreationTime'),
                    'RegionId': acl.get('RegionId'),
                    'OwnerId': acl.get('OwnerId'),
                    'IngressRules': [],
                    'EgressRules': [],
                    'AssociatedResources': [],
                    'Tags': acl.get('Tags', {}).get('Tag', [])
                }
                
                # 处理入方向规则
                ingress_entries = acl.get('IngressAclEntries', {}).get('IngressAclEntry', [])
                for entry in ingress_entries:
                    rule_info = {
                        'NetworkAclEntryId': entry.get('NetworkAclEntryId'),
                        'NetworkAclEntryName': entry.get('NetworkAclEntryName'),
                        'Policy': entry.get('Policy'),
                        'Protocol': entry.get('Protocol'),
                        'SourceCidrIp': entry.get('SourceCidrIp'),
                        'Port': entry.get('Port'),
                        'Description': entry.get('Description'),
                        'EntryType': entry.get('EntryType'),
                        'IpVersion': entry.get('IpVersion'),
                    }
                    acl_info['IngressRules'].append(rule_info)
                
                # 处理出方向规则
                egress_entries = acl.get('EgressAclEntries', {}).get('EgressAclEntry', [])
                for entry in egress_entries:
                    rule_info = {
                        'NetworkAclEntryId': entry.get('NetworkAclEntryId'),
                        'NetworkAclEntryName': entry.get('NetworkAclEntryName'),
                        'Policy': entry.get('Policy'),
                        'Protocol': entry.get('Protocol'),
                        'DestinationCidrIp': entry.get('DestinationCidrIp'),
                        'Port': entry.get('Port'),
                        'Description': entry.get('Description'),
                        'EntryType': entry.get('EntryType'),
                        'IpVersion': entry.get('IpVersion'),
                    }
                    acl_info['EgressRules'].append(rule_info)
                
                # 处理关联的资源
                resources = acl.get('Resources', {}).get('Resource', [])
                for resource in resources:
                    resource_info = {
                        'ResourceId': resource.get('ResourceId'),
                        'ResourceType': resource.get('ResourceType'),
                        'Status': resource.get('Status'),
                    }
                    acl_info['AssociatedResources'].append(resource_info)
                
                network_acls.append(acl_info)
                
        except Exception as e:
            logger.error(f"获取网络ACL信息失败: {str(e)}")
        
        return network_acls

    def get_all_network_assets(self) -> Dict[str, Any]:
        """
        获取所有网络资源

        Returns:
            Dict[str, Any]: 所有网络资源
        """
        logger.info("获取所有阿里云网络资源")
        
        # 获取各类网络资源
        vpcs = self.get_vpcs()
        vswitches = self.get_vswitches()
        security_groups = self.get_security_groups()
        route_tables = self.get_route_tables()
        network_acls = self.get_network_acls()
        
        # 组织返回结果
        network_assets = {
            'vpcs': {vpc['VpcId']: vpc for vpc in vpcs},
            'vswitches': {vswitch['VSwitchId']: vswitch for vswitch in vswitches},
            'security_groups': {sg['SecurityGroupId']: sg for sg in security_groups},
            'route_tables': {rt['RouteTableId']: rt for rt in route_tables},
            'network_acls': {acl['NetworkAclId']: acl for acl in network_acls},
        }
        
        logger.info(f"已获取 {len(vpcs)} 个VPC, {len(vswitches)} 个交换机, {len(security_groups)} 个安全组, {len(route_tables)} 个路由表, {len(network_acls)} 个网络ACL")
        return network_assets