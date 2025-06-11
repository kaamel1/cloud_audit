"""阿里云域名与路由全局资源处理模块，负责获取DNS、域名等全局资源信息。"""
import logging
from typing import Dict, List, Any
import importlib

logger = logging.getLogger(__name__)

class DomainRouterGlobalAssetCollector:
    """阿里云域名与路由全局资源收集器"""

    def __init__(self, session):
        """
        初始化域名与路由全局资源收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        # 初始化各个域名服务的客户端
        self.dns_client = session.get_client('dns')
        self.domain_client = session.get_client('domain')
        self.cdn_client = session.get_client('cdn')

    def _check_api_availability(self, service_name, action):
        """
        检查API是否可用
        
        Args:
            service_name: 服务名称
            action: API操作名称
            
        Returns:
            bool: API是否可用
        """
        try:
            # 尝试获取请求类
            if service_name == 'domain':
                # 尝试不同版本的域名API
                api_versions = [
                    'aliyunsdkdomain.request.v20180129',
                    'aliyunsdkdomain.request.v20180208', 
                    'aliyunsdkdomain.request.v20210325'
                ]
            elif service_name == 'dns':
                # 尝试不同版本的DNS API
                api_versions = [
                    'aliyunsdkalidns.request.v20150109',
                    'aliyunsdkalidns.request.v20180208',
                    'aliyunsdkalidns.request.v20190117'
                ]
            else:
                return False
                
            for api_version in api_versions:
                try:
                    # 构造完整的请求类模块路径
                    request_class_name = f"{action}Request"
                    request_module_path = f"{api_version}.{request_class_name}"
                    
                    # 尝试导入具体的请求类模块
                    try:
                        request_module = importlib.import_module(request_module_path)
                        # 如果成功导入，说明API可用
                        logger.debug(f"API {service_name}.{action} 在版本 {api_version} 中可用")
                        return True
                    except ImportError:
                        # 如果导入失败，尝试从版本模块中获取请求类
                        version_module = importlib.import_module(api_version)
                        if hasattr(version_module, request_class_name):
                            logger.debug(f"API {service_name}.{action} 在版本模块 {api_version} 中可用")
                            return True
                except ImportError:
                    continue
            
            return False
        except Exception:
            return False

    def get_domains(self) -> List[Dict[str, Any]]:
        """
        获取域名信息

        Returns:
            List[Dict[str, Any]]: 域名列表
        """
        logger.info("获取域名信息")
        domains = []

        # 首先检查API是否可用
        if not self._check_api_availability('domain', 'QueryDomainList'):
            logger.warning("域名API不可用，可能是SDK版本不匹配，尝试替代方法")
            
            try:
                # 尝试使用其他可能的API
                alternative_actions = [
                    'QueryDomainList', 
                    'ListDomains',      # 可能的替代API
                    'DescribeDomains'   # 可能的替代API
                ]
                
                for action in alternative_actions:
                    try:
                        request = self.session.create_request('domain', action)
                        response = self.session.do_action_with_exception(request)
                        response_dict = self.session.parse_response(response)
                        
                        # 根据不同API调整结果解析
                        if action == 'QueryDomainList':
                            domains_data = response_dict.get('Data', {}).get('Domain', [])
                        elif action == 'ListDomains':
                            domains_data = response_dict.get('Domains', [])
                        elif action == 'DescribeDomains':
                            domains_data = response_dict.get('Domains', {}).get('Domain', [])
                        else:
                            domains_data = []
                        
                        for domain in domains_data:
                            domain_info = {
                                'DomainName': domain.get('DomainName'),
                                'InstanceId': domain.get('InstanceId'),
                                'ExpirationDate': domain.get('ExpirationDate', domain.get('Expiration')),
                                'RegistrationDate': domain.get('RegistrationDate', domain.get('Creation')),
                                'DomainStatus': domain.get('DomainStatus', domain.get('Status')),
                            }
                            domains.append(domain_info)
                        
                        if domains:
                            logger.info(f"成功使用 {action} API获取域名信息")
                            break
                    except Exception as e:
                        logger.debug(f"尝试使用 {action} API获取域名信息失败: {str(e)}")
                        continue
            except Exception as e:
                logger.error(f"获取域名信息失败: {str(e)}")
            
            return domains

        try:
            # 获取所有域名 - 设置初始分页参数
            request = self.session.create_request('domain', 'QueryDomainList')
            # 使用Domain SDK的专用方法设置参数
            if hasattr(request, 'set_PageNum'):
                request.set_PageNum(1)  # 设置初始页码
                request.set_PageSize(50)  # 设置页面大小
            else:
                # 如果是MockRequest，使用通用方法
                request.set_query_param('PageNum', 1)
                request.set_query_param('PageSize', 50)
            response = self.session.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)

            for domain in response_dict.get('Data', {}).get('Domain', []):
                domain_info = {
                    'DomainName': domain.get('DomainName'),
                    'InstanceId': domain.get('InstanceId'),
                    'ExpirationDate': domain.get('ExpirationDate'),
                    'RegistrationDate': domain.get('RegistrationDate'),
                    'DomainStatus': domain.get('DomainStatus'),
                    'DomainType': domain.get('DomainType'),
                    'Premium': domain.get('Premium'),
                    'DomainAuditStatus': domain.get('DomainAuditStatus'),
                    'ProductId': domain.get('ProductId'),
                    'ExpirationDateLong': domain.get('ExpirationDateLong'),
                    'RegistrationDateLong': domain.get('RegistrationDateLong'),
                }
                domains.append(domain_info)

            # 处理分页
            page_number = 1
            page_size = response_dict.get('PageSize', 50)
            while response_dict.get('TotalItemNum', 0) > page_number * page_size:
                page_number += 1
                request = self.session.create_request('domain', 'QueryDomainList')
                # 使用Domain SDK的专用方法设置参数
                if hasattr(request, 'set_PageNum'):
                    request.set_PageNum(page_number)
                    request.set_PageSize(page_size)
                else:
                    # 如果是MockRequest，使用通用方法
                    request.set_query_param('PageNum', page_number)
                    request.set_query_param('PageSize', page_size)
                response = self.session.do_action_with_exception(request)
                response_dict = self.session.parse_response(response)

                for domain in response_dict.get('Data', {}).get('Domain', []):
                    domain_info = {
                        'DomainName': domain.get('DomainName'),
                        'InstanceId': domain.get('InstanceId'),
                        'ExpirationDate': domain.get('ExpirationDate'),
                        'RegistrationDate': domain.get('RegistrationDate'),
                        'DomainStatus': domain.get('DomainStatus'),
                        'DomainType': domain.get('DomainType'),
                        'Premium': domain.get('Premium'),
                        'DomainAuditStatus': domain.get('DomainAuditStatus'),
                        'ProductId': domain.get('ProductId'),
                        'ExpirationDateLong': domain.get('ExpirationDateLong'),
                        'RegistrationDateLong': domain.get('RegistrationDateLong'),
                    }
                    domains.append(domain_info)

        except Exception as e:
            error_msg = str(e)
            # 特别处理权限相关错误
            if 'Forbidden.RAM' in error_msg or 'not authorized' in error_msg:
                logger.warning(f"域名服务访问被拒绝: 当前RAM用户没有域名服务权限，或该API不支持RAM用户访问")
                logger.warning(f"建议: 请使用主账号访问密钥，或为RAM用户添加域名服务相关权限")
                logger.debug(f"详细错误信息: {error_msg}")
            elif 'InvalidAccessKeyId' in error_msg:
                logger.error(f"认证失败: 访问密钥无效或不存在")
                logger.debug(f"详细错误信息: {error_msg}")
            else:
                logger.error(f"获取域名信息失败: {error_msg}")

        return domains

    def get_dns_domains(self) -> List[Dict[str, Any]]:
        """
        获取DNS域名信息

        Returns:
            List[Dict[str, Any]]: DNS域名列表
        """
        logger.info("获取DNS域名信息")
        dns_domains = []

        # 首先检查API是否可用
        if not self._check_api_availability('dns', 'DescribeDomains'):
            logger.warning("DNS API不可用，可能是SDK版本不匹配，尝试替代方法")
            
            try:
                # 尝试使用其他可能的API
                alternative_actions = [
                    'DescribeDomains', 
                    'ListDomains',      # 可能的替代API
                    'QueryDomainList'   # 可能的替代API
                ]
                
                for action in alternative_actions:
                    try:
                        request = self.session.create_request('dns', action)
                        response = self.session.do_action_with_exception(request)
                        response_dict = self.session.parse_response(response)
                        
                        # 根据不同API调整结果解析
                        if action == 'DescribeDomains':
                            domains_data = response_dict.get('Domains', {}).get('Domain', [])
                        elif action == 'ListDomains':
                            domains_data = response_dict.get('Domains', [])
                        elif action == 'QueryDomainList':
                            domains_data = response_dict.get('Data', {}).get('Domain', [])
                        else:
                            domains_data = []
                        
                        for domain in domains_data:
                            domain_info = {
                                'DomainName': domain.get('DomainName'),
                                'DomainId': domain.get('DomainId', domain.get('InstanceId')),
                                'RecordCount': domain.get('RecordCount', 0),
                            }
                            dns_domains.append(domain_info)
                        
                        if dns_domains:
                            logger.info(f"成功使用 {action} API获取DNS域名信息")
                            break
                    except Exception as e:
                        logger.debug(f"尝试使用 {action} API获取DNS域名信息失败: {str(e)}")
                        continue
            except Exception as e:
                logger.error(f"获取DNS域名信息失败: {str(e)}")
            
            return dns_domains

        try:
            # 获取所有DNS域名
            request = self.session.create_request('dns', 'DescribeDomains')
            response = self.session.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)

            for domain in response_dict.get('Domains', {}).get('Domain', []):
                domain_info = {
                    'DomainId': domain.get('DomainId'),
                    'DomainName': domain.get('DomainName'),
                    'AliDomain': domain.get('AliDomain'),
                    'GroupId': domain.get('GroupId'),
                    'GroupName': domain.get('GroupName'),
                    'InstanceId': domain.get('InstanceId'),
                    'VersionCode': domain.get('VersionCode'),
                    'PunyCode': domain.get('PunyCode'),
                    'DnsServers': domain.get('DnsServers', {}).get('DnsServer', []),
                    'RecordCount': domain.get('RecordCount'),
                    'RegistrantEmail': domain.get('RegistrantEmail'),
                    'Remark': domain.get('Remark'),
                    'CreateTime': domain.get('CreateTime'),
                    'CreateTimestamp': domain.get('CreateTimestamp'),
                    'UpdateTime': domain.get('UpdateTime'),
                    'UpdateTimestamp': domain.get('UpdateTimestamp'),
                }
                dns_domains.append(domain_info)

            # 处理分页
            page_number = 1
            while response_dict.get('TotalCount', 0) > page_number * response_dict.get('PageSize', 0):
                page_number += 1
                request = self.session.create_request('dns', 'DescribeDomains')
                # 使用DNS SDK的专用方法设置参数
                if hasattr(request, 'set_PageNumber'):
                    request.set_PageNumber(page_number)
                else:
                    # 如果是MockRequest，使用通用方法
                    request.set_query_param('PageNumber', page_number)
                response = self.session.do_action_with_exception(request)
                response_dict = self.session.parse_response(response)

                for domain in response_dict.get('Domains', {}).get('Domain', []):
                    domain_info = {
                        'DomainId': domain.get('DomainId'),
                        'DomainName': domain.get('DomainName'),
                        'AliDomain': domain.get('AliDomain'),
                        'GroupId': domain.get('GroupId'),
                        'GroupName': domain.get('GroupName'),
                        'InstanceId': domain.get('InstanceId'),
                        'VersionCode': domain.get('VersionCode'),
                        'PunyCode': domain.get('PunyCode'),
                        'DnsServers': domain.get('DnsServers', {}).get('DnsServer', []),
                        'RecordCount': domain.get('RecordCount'),
                        'RegistrantEmail': domain.get('RegistrantEmail'),
                        'Remark': domain.get('Remark'),
                        'CreateTime': domain.get('CreateTime'),
                        'CreateTimestamp': domain.get('CreateTimestamp'),
                        'UpdateTime': domain.get('UpdateTime'),
                        'UpdateTimestamp': domain.get('UpdateTimestamp'),
                    }
                    dns_domains.append(domain_info)

        except Exception as e:
            error_msg = str(e)
            # 特别处理权限相关错误
            if 'Forbidden.RAM' in error_msg or 'not authorized' in error_msg:
                logger.warning(f"DNS服务访问被拒绝: 当前RAM用户没有DNS服务权限，或该API不支持RAM用户访问")
                logger.warning(f"建议: 请使用主账号访问密钥，或为RAM用户添加DNS服务相关权限")
                logger.debug(f"详细错误信息: {error_msg}")
            elif 'InvalidAccessKeyId' in error_msg:
                logger.error(f"认证失败: 访问密钥无效或不存在")
                logger.debug(f"详细错误信息: {error_msg}")
            else:
                logger.error(f"获取DNS域名信息失败: {error_msg}")

        return dns_domains

    def get_dns_records(self, domain_name: str) -> List[Dict[str, Any]]:
        """
        获取指定域名的DNS记录

        Args:
            domain_name: 域名名称

        Returns:
            List[Dict[str, Any]]: DNS记录列表
        """
        logger.info(f"获取域名 {domain_name} 的DNS记录")
        records = []

        # 首先检查API是否可用
        if not self._check_api_availability('dns', 'DescribeDomainRecords'):
            logger.warning(f"DNS记录API不可用，可能是SDK版本不匹配，跳过获取域名 {domain_name} 的DNS记录")
            return records

        try:
            # 获取指定域名的所有DNS记录
            request = self.session.create_request('dns', 'DescribeDomainRecords')
            # 使用DNS SDK的专用方法设置参数
            if hasattr(request, 'set_DomainName'):
                request.set_DomainName(domain_name)
            else:
                # 如果是MockRequest，使用通用方法
                request.set_query_param('DomainName', domain_name)
            response = self.session.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)

            for record in response_dict.get('DomainRecords', {}).get('Record', []):
                record_info = {
                    'RecordId': record.get('RecordId'),
                    'RR': record.get('RR'),
                    'Type': record.get('Type'),
                    'Value': record.get('Value'),
                    'TTL': record.get('TTL'),
                    'Priority': record.get('Priority'),
                    'Line': record.get('Line'),
                    'Status': record.get('Status'),
                    'Locked': record.get('Locked'),
                    'Weight': record.get('Weight'),
                    'Remark': record.get('Remark'),
                }
                records.append(record_info)

            # 处理分页
            page_number = 1
            while response_dict.get('TotalCount', 0) > page_number * response_dict.get('PageSize', 0):
                page_number += 1
                request = self.session.create_request('dns', 'DescribeDomainRecords')
                # 使用DNS SDK的专用方法设置参数
                if hasattr(request, 'set_DomainName'):
                    request.set_DomainName(domain_name)
                    request.set_PageNumber(page_number)
                else:
                    # 如果是MockRequest，使用通用方法
                    request.set_query_param('DomainName', domain_name)
                    request.set_query_param('PageNumber', page_number)
                response = self.session.do_action_with_exception(request)
                response_dict = self.session.parse_response(response)

                for record in response_dict.get('DomainRecords', {}).get('Record', []):
                    record_info = {
                        'RecordId': record.get('RecordId'),
                        'RR': record.get('RR'),
                        'Type': record.get('Type'),
                        'Value': record.get('Value'),
                        'TTL': record.get('TTL'),
                        'Priority': record.get('Priority'),
                        'Line': record.get('Line'),
                        'Status': record.get('Status'),
                        'Locked': record.get('Locked'),
                        'Weight': record.get('Weight'),
                        'Remark': record.get('Remark'),
                    }
                    records.append(record_info)

        except Exception as e:
            error_msg = str(e)
            # 特别处理权限相关错误
            if 'Forbidden.RAM' in error_msg or 'not authorized' in error_msg:
                logger.warning(f"DNS记录服务访问被拒绝: 当前RAM用户没有DNS记录查询权限")
                logger.warning(f"建议: 请使用主账号访问密钥，或为RAM用户添加DNS记录查询权限")
                logger.debug(f"详细错误信息: {error_msg}")
            elif 'InvalidAccessKeyId' in error_msg:
                logger.error(f"认证失败: 访问密钥无效或不存在")
                logger.debug(f"详细错误信息: {error_msg}")
            else:
                logger.error(f"获取域名 {domain_name} 的DNS记录失败: {error_msg}")

        return records

    def get_cdn_domain_detail(self, domain_name: str) -> Dict[str, Any]:
        """
        获取指定CDN域名的详细配置信息
        
        Args:
            domain_name: 域名名称
            
        Returns:
            Dict[str, Any]: 域名详细配置信息
        """
        logger.debug(f"获取CDN域名 {domain_name} 的详细配置")
        
        try:
            # 获取域名详细配置
            request = self.session.create_request('cdn', 'DescribeCdnDomainDetail')
            if hasattr(request, 'set_DomainName'):
                request.set_DomainName(domain_name)
            else:
                request.set_query_param('DomainName', domain_name)
            
            response = self.session.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            # 直接返回域名详细配置
            return response_dict.get('GetDomainDetailModel', {})
            
        except Exception as e:
            logger.debug(f"获取CDN域名 {domain_name} 详细配置失败: {str(e)}")
            return {}

    def get_cdn_domains(self) -> List[Dict[str, Any]]:
        """
        获取CDN域名信息，包括详细配置

        Returns:
            List[Dict[str, Any]]: CDN域名列表
        """
        logger.info("获取CDN域名信息")
        cdn_domains = []

        try:
            # 获取所有CDN域名
            request = self.session.create_request('cdn', 'DescribeUserDomains')
            response = self.session.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)

            for domain in response_dict.get('Domains', {}).get('PageData', []):
                domain_name = domain.get('DomainName')
                
                # 基本域名信息
                domain_info = {
                    'DomainName': domain_name,
                    'Cname': domain.get('Cname'),
                    'CdnType': domain.get('CdnType'),
                    'DomainStatus': domain.get('DomainStatus'),
                    'GmtCreated': domain.get('GmtCreated'),
                    'GmtModified': domain.get('GmtModified'),
                    'Description': domain.get('Description'),
                    'ResourceGroupId': domain.get('ResourceGroupId'),
                    'SslProtocol': domain.get('SslProtocol'),
                    'Coverage': domain.get('Coverage'),
                    'Sandbox': domain.get('Sandbox'),
                }
                
                # 获取并追加域名详细配置
                if domain_name:
                    domain_detail = self.get_cdn_domain_detail(domain_name)
                    if domain_detail:
                        # 直接追加详细配置到域名信息中
                        domain_info.update(domain_detail)
                
                cdn_domains.append(domain_info)

            # 处理分页
            page_number = 1
            while response_dict.get('TotalCount', 0) > page_number * response_dict.get('PageSize', 0):
                page_number += 1
                request = self.session.create_request('cdn', 'DescribeUserDomains')
                # 使用CDN SDK的专用方法设置参数
                if hasattr(request, 'set_PageNumber'):
                    request.set_PageNumber(page_number)
                else:
                    # 如果是MockRequest，使用通用方法
                    request.set_query_param('PageNumber', page_number)
                response = self.session.do_action_with_exception(request)
                response_dict = self.session.parse_response(response)

                for domain in response_dict.get('Domains', {}).get('PageData', []):
                    domain_name = domain.get('DomainName')
                    
                    # 基本域名信息
                    domain_info = {
                        'DomainName': domain_name,
                        'Cname': domain.get('Cname'),
                        'CdnType': domain.get('CdnType'),
                        'DomainStatus': domain.get('DomainStatus'),
                        'GmtCreated': domain.get('GmtCreated'),
                        'GmtModified': domain.get('GmtModified'),
                        'Description': domain.get('Description'),
                        'ResourceGroupId': domain.get('ResourceGroupId'),
                        'SslProtocol': domain.get('SslProtocol'),
                        'Coverage': domain.get('Coverage'),
                        'Sandbox': domain.get('Sandbox'),
                    }
                    
                    # 获取并追加域名详细配置
                    if domain_name:
                        domain_detail = self.get_cdn_domain_detail(domain_name)
                        if domain_detail:
                            # 直接追加详细配置到域名信息中
                            domain_info.update(domain_detail)
                    
                    cdn_domains.append(domain_info)

        except Exception as e:
            error_msg = str(e)
            # 特别处理权限相关错误
            if 'Forbidden.RAM' in error_msg or 'not authorized' in error_msg:
                logger.warning(f"CDN服务访问被拒绝: 当前RAM用户没有CDN服务权限，或该API不支持RAM用户访问")
                logger.warning(f"建议: 请使用主账号访问密钥，或为RAM用户添加CDN服务相关权限")
                logger.debug(f"详细错误信息: {error_msg}")
            elif 'InvalidAccessKeyId' in error_msg:
                logger.error(f"认证失败: 访问密钥无效或不存在")
                logger.debug(f"详细错误信息: {error_msg}")
            else:
                logger.error(f"获取CDN域名信息失败: {error_msg}")

        return cdn_domains

    def get_all_domain_router_global_assets(self) -> Dict[str, Any]:
        """
        获取所有域名与路由全局资产信息

        Returns:
            Dict[str, Any]: 所有域名与路由全局资产信息
        """
        logger.info("获取所有域名与路由全局资产信息")
        
        # 获取各类域名信息
        domains = self.get_domains()
        dns_domains = self.get_dns_domains()
        cdn_domains = self.get_cdn_domains()
        
        # 获取DNS记录
        dns_records = {}
        for domain in dns_domains:
            domain_name = domain.get('DomainName')
            if domain_name:
                dns_records[domain_name] = self.get_dns_records(domain_name)
        
        # 整合所有域名与路由资产信息
        domain_router_assets = {
            'domains': {domain['DomainName']: domain for domain in domains},
            'dns_domains': {domain['DomainName']: domain for domain in dns_domains},
            'dns_records': dns_records,
            'cdn_domains': {domain['DomainName']: domain for domain in cdn_domains},
        }
        
        return domain_router_assets