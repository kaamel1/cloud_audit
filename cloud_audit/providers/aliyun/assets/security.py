"""阿里云安全资源处理模块，负责获取云安全中心、WAF、DDoS防护等资源信息。"""
import logging
import importlib.util
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class SecurityAssetCollector:
    """阿里云安全资源收集器"""

    def __init__(self, session):
        """
        初始化安全资源收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        
        # 检查是否安装了必要的SDK
        self.has_sas_sdk = importlib.util.find_spec("aliyunsdksas") is not None
        self.has_waf_sdk = importlib.util.find_spec("aliyunsdkwaf_openapi") is not None
        self.has_ddos_sdk = importlib.util.find_spec("aliyunsdkddoscoo") is not None
        
        if not self.has_sas_sdk:
            logger.warning("缺少aliyunsdksas SDK，无法获取云安全中心数据。请使用pip安装: pip install aliyun-python-sdk-sas")
        if not self.has_waf_sdk:
            logger.warning("缺少aliyunsdkwaf_openapi SDK，无法获取WAF数据。请使用pip安装: pip install aliyun-python-sdk-waf-openapi")
        if not self.has_ddos_sdk:
            logger.warning("缺少aliyunsdkddoscoo SDK，无法获取DDoS高防数据。请使用pip安装: pip install aliyun-python-sdk-ddoscoo")
        
        # 初始化各个安全服务的客户端
        try:
            self.security_center_client = session.get_client('sas') if self.has_sas_sdk else None  # 云安全中心
        except Exception as e:
            logger.error(f"初始化云安全中心客户端失败: {str(e)}")
            self.security_center_client = None
            self.has_sas_sdk = False
            
        try:
            self.waf_client = session.get_client('waf-openapi') if self.has_waf_sdk else None  # Web应用防火墙
        except Exception as e:
            logger.error(f"初始化WAF客户端失败: {str(e)}")
            self.waf_client = None
            self.has_waf_sdk = False
            
        try:
            self.ddos_client = session.get_client('ddoscoo') if self.has_ddos_sdk else None  # DDoS高防
        except Exception as e:
            logger.error(f"初始化DDoS高防客户端失败: {str(e)}")
            self.ddos_client = None
            self.has_ddos_sdk = False

    def get_security_center_assets(self) -> Dict[str, Any]:
        """
        获取云安全中心资产信息

        Returns:
            Dict[str, Any]: 云安全中心资产信息
        """
        logger.info("获取云安全中心资产信息")
        assets = {
            'overview': {},
            'vulnerabilities': [],
            'baseline_risks': [],
            'security_events': [],
        }

        # 检查SDK是否可用
        if not self.has_sas_sdk or not self.security_center_client:
            logger.warning("缺少aliyunsdksas SDK，无法获取云安全中心资产信息")
            assets['error'] = "缺少aliyunsdksas SDK，请使用pip安装: pip install aliyun-python-sdk-sas"
            return assets

        try:
            # 获取安全中心概览
            from aliyunsdksas.request.v20181203.DescribeSecurityStatInfoRequest import DescribeSecurityStatInfoRequest
            
            request = DescribeSecurityStatInfoRequest()
            request.set_accept_format('json')
            
            response = self.security_center_client.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            assets['overview'] = {
                'account_count': response_dict.get('AccountCount'),
                'protect_asset_count': response_dict.get('ProtectAssetCount'),
                'unprotect_asset_count': response_dict.get('UnprotectAssetCount'),
                'protect_asset_percent': response_dict.get('ProtectAssetPercent'),
                'high_vulnerability_count': response_dict.get('HighVulnerabilityCount'),
                'medium_vulnerability_count': response_dict.get('MediumVulnerabilityCount'),
                'low_vulnerability_count': response_dict.get('LowVulnerabilityCount'),
                'baseline_risk_count': response_dict.get('BaselineRiskCount'),
                'security_score': response_dict.get('SecurityScore'),
            }

            # 获取漏洞列表
            self._get_vulnerabilities(assets)
            
            # 获取基线检查风险
            self._get_baseline_risks(assets)
            
            # 获取安全告警事件
            self._get_security_events(assets)
            
        except ImportError:
            logger.error("无法导入aliyunsdksas模块，请安装相应的SDK")
            assets['error'] = "缺少aliyunsdksas SDK，请使用pip安装: pip install aliyun-python-sdk-sas"
        except Exception as e:
            logger.error(f"获取云安全中心资产信息失败: {str(e)}")
            assets['error'] = f"获取云安全中心资产信息失败: {str(e)}"

        return assets

    def _get_vulnerabilities(self, assets: Dict[str, Any]) -> None:
        """
        获取漏洞信息

        Args:
            assets: 安全中心资产字典，用于存储结果
        """
        # 检查SDK是否可用
        if not self.has_sas_sdk or not self.security_center_client:
            logger.warning("缺少aliyunsdksas SDK，无法获取漏洞信息")
            return

        try:
            # 获取漏洞列表
            from aliyunsdksas.request.v20181203.DescribeVulListRequest import DescribeVulListRequest
            
            request = DescribeVulListRequest()
            request.set_accept_format('json')
            request.set_PageSize(50)
            request.set_CurrentPage(1)
            # Type是必填参数，这里获取Linux软件漏洞
            request.set_Type('cve')
            
            response = self.security_center_client.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            # 处理漏洞数据
            for vuln in response_dict.get('VulnerabilityList', []):
                vuln_info = {
                    'uuid': vuln.get('Uuid'),
                    'name': vuln.get('Name'),
                    'aliases': vuln.get('AliasName'),
                    'type': vuln.get('Type'),
                    'level': vuln.get('Level'),
                    'status': vuln.get('Status'),
                    'host_count': vuln.get('HostCount'),
                    'last_scan_time': vuln.get('LastScanTime'),
                }
                assets['vulnerabilities'].append(vuln_info)
                
            # 处理分页
            total_count = response_dict.get('TotalCount', 0)
            page_size = response_dict.get('PageSize', 50)
            current_page = 1
            
            while total_count > current_page * page_size and current_page < 5:  # 限制获取前5页
                current_page += 1
                
                request = DescribeVulListRequest()
                request.set_accept_format('json')
                request.set_PageSize(page_size)
                request.set_CurrentPage(current_page)
                # Type是必填参数，这里获取Linux软件漏洞
                request.set_Type('cve')
                
                response = self.security_center_client.do_action_with_exception(request)
                response_dict = self.session.parse_response(response)
                
                # 处理漏洞数据
                for vuln in response_dict.get('VulnerabilityList', []):
                    vuln_info = {
                        'uuid': vuln.get('Uuid'),
                        'name': vuln.get('Name'),
                        'aliases': vuln.get('AliasName'),
                        'type': vuln.get('Type'),
                        'level': vuln.get('Level'),
                        'status': vuln.get('Status'),
                        'host_count': vuln.get('HostCount'),
                        'last_scan_time': vuln.get('LastScanTime'),
                    }
                    assets['vulnerabilities'].append(vuln_info)
                    
        except ImportError:
            logger.error("无法导入aliyunsdksas模块，请安装相应的SDK")
        except Exception as e:
            logger.error(f"获取漏洞信息失败: {str(e)}")

    def _get_baseline_risks(self, assets: Dict[str, Any]) -> None:
        """
        获取基线检查风险

        Args:
            assets: 安全中心资产字典，用于存储结果
        """
        # 检查SDK是否可用
        if not self.has_sas_sdk or not self.security_center_client:
            logger.warning("缺少aliyunsdksas SDK，无法获取基线检查风险")
            return

        try:
            # 先获取服务器列表，然后为每个服务器获取基线检查风险
            from aliyunsdksas.request.v20181203.DescribeCloudCenterInstancesRequest import DescribeCloudCenterInstancesRequest
            
            # 获取服务器列表
            request = DescribeCloudCenterInstancesRequest()
            request.set_accept_format('json')
            request.set_PageSize(50)
            request.set_CurrentPage(1)
            
            response = self.security_center_client.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            instances = response_dict.get('Instances', [])
            if not instances:
                logger.info("没有找到服务器实例，无法获取基线检查风险")
                return
            
            # 为每个服务器获取基线检查风险 (最多处理前10个服务器)
            from aliyunsdksas.request.v20181203.DescribeCheckWarningsRequest import DescribeCheckWarningsRequest
            
            for i, instance in enumerate(instances[:10]):  # 限制处理前10个服务器
                uuid = instance.get('Uuid')
                if not uuid:
                    continue
                    
                try:
                    request = DescribeCheckWarningsRequest()
                    request.set_accept_format('json')
                    request.set_PageSize(20)  # 每个服务器获取20条记录
                    request.set_CurrentPage(1)
                    request.set_Uuid(uuid)  # 设置必需的UUID参数
                    
                    response = self.security_center_client.do_action_with_exception(request)
                    response_dict = self.session.parse_response(response)
                    
                    # 处理基线检查风险数据
                    for risk in response_dict.get('CheckWarnings', []):
                        risk_info = {
                            'uuid': uuid,
                            'instance_name': instance.get('InstanceName'),
                            'item': risk.get('Item'),
                            'level': risk.get('Level'),
                            'type': risk.get('Type'),
                            'status': risk.get('Status'),
                            'check_id': risk.get('CheckId'),
                            'container_name': risk.get('ContainerName'),
                        }
                        assets['baseline_risks'].append(risk_info)
                        
                except Exception as e:
                    logger.warning(f"获取服务器 {uuid} 的基线检查风险失败: {str(e)}")
                    continue
                    
        except ImportError:
            logger.error("无法导入aliyunsdksas模块，请安装相应的SDK")
        except Exception as e:
            logger.error(f"获取基线检查风险失败: {str(e)}")

    def _get_security_events(self, assets: Dict[str, Any]) -> None:
        """
        获取安全告警事件

        Args:
            assets: 安全中心资产字典，用于存储结果
        """
        # 检查SDK是否可用
        if not self.has_sas_sdk or not self.security_center_client:
            logger.warning("缺少aliyunsdksas SDK，无法获取安全告警事件")
            return

        try:
            # 获取安全告警事件列表
            from aliyunsdksas.request.v20181203.DescribeSuspEventsRequest import DescribeSuspEventsRequest
            
            request = DescribeSuspEventsRequest()
            request.set_accept_format('json')
            request.set_PageSize(50)
            request.set_CurrentPage(1)
            
            response = self.security_center_client.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            # 处理安全告警事件数据
            for event in response_dict.get('SecurityEventList', []):
                event_info = {
                    'uuid': event.get('Uuid'),
                    'name': event.get('Name'),
                    'level': event.get('Level'),
                    'event_type': event.get('EventType'),
                    'status': event.get('Status'),
                    'instance_name': event.get('InstanceName'),
                    'instance_id': event.get('InstanceId'),
                    'internet_ip': event.get('InternetIp'),
                    'intranet_ip': event.get('IntranetIp'),
                    'event_time': event.get('EventTime'),
                }
                assets['security_events'].append(event_info)
                
            # 处理分页
            total_count = response_dict.get('TotalCount', 0)
            page_size = response_dict.get('PageSize', 50)
            current_page = 1
            
            while total_count > current_page * page_size and current_page < 5:  # 限制获取前5页
                current_page += 1
                
                request = DescribeSuspEventsRequest()
                request.set_accept_format('json')
                request.set_PageSize(page_size)
                request.set_CurrentPage(current_page)
                
                response = self.security_center_client.do_action_with_exception(request)
                response_dict = self.session.parse_response(response)
                
                # 处理安全告警事件数据
                for event in response_dict.get('SecurityEventList', []):
                    event_info = {
                        'uuid': event.get('Uuid'),
                        'name': event.get('Name'),
                        'level': event.get('Level'),
                        'event_type': event.get('EventType'),
                        'status': event.get('Status'),
                        'instance_name': event.get('InstanceName'),
                        'instance_id': event.get('InstanceId'),
                        'internet_ip': event.get('InternetIp'),
                        'intranet_ip': event.get('IntranetIp'),
                        'event_time': event.get('EventTime'),
                    }
                    assets['security_events'].append(event_info)
                    
        except ImportError:
            logger.error("无法导入aliyunsdksas模块，请安装相应的SDK")
        except Exception as e:
            logger.error(f"获取安全告警事件失败: {str(e)}")

    def get_waf_instances(self) -> List[Dict[str, Any]]:
        """
        获取WAF实例信息

        Returns:
            List[Dict[str, Any]]: WAF实例列表
        """
        logger.info("获取WAF实例信息")
        instances = []

        # 检查SDK是否可用
        if not self.has_waf_sdk or not self.waf_client:
            logger.warning("缺少aliyunsdkwaf_openapi SDK，无法获取WAF实例信息")
            return instances

        try:
            # 获取WAF实例
            from aliyunsdkwaf_openapi.request.v20190910 import DescribeInstanceInfoRequest
            
            request = DescribeInstanceInfoRequest.DescribeInstanceInfoRequest()
            request.set_accept_format('json')
            
            response = self.waf_client.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            # 调试：打印原始响应
            logger.debug(f"WAF实例API原始响应: {response_dict}")
            
            # 处理WAF实例数据
            # WAF API返回结构可能包含InstanceInfo子对象
            instance_data = response_dict.get('InstanceInfo', response_dict)
            
            instance_info = {
                'instance_id': response_dict.get('InstanceId') or instance_data.get('InstanceId'),
                'end_date': response_dict.get('EndDate') or instance_data.get('EndDate'),
                'in_debt': response_dict.get('InDebt') or instance_data.get('InDebt'),
                'pay_type': response_dict.get('PayType') or instance_data.get('PayType'),
                'region': response_dict.get('Region') or instance_data.get('Region'),
                'trial': response_dict.get('Trial') or instance_data.get('Trial'),
                'edition': response_dict.get('Edition') or instance_data.get('Edition'),
                'subscription_type': response_dict.get('SubscriptionType') or instance_data.get('SubscriptionType'),
            }
            
            # 检查是否获取到了实例ID
            if not instance_info['instance_id']:
                pay_type = instance_info.get('pay_type')
                if pay_type == 0:
                    logger.info("WAF账户已开通但使用按量付费模式，当前没有激活实例")
                else:
                    logger.debug(f"WAF实例API响应中没有InstanceId字段，完整响应: {response_dict}")
                    logger.info("账户支持WAF服务但可能尚未创建实例")
            else:
                logger.info(f"成功获取WAF实例ID: {instance_info['instance_id']}")
            
            instances.append(instance_info)
            
        except ImportError:
            logger.error("无法导入aliyunsdkwaf_openapi模块，请安装相应的SDK")
        except Exception as e:
            logger.error(f"获取WAF实例信息失败: {str(e)}")
            logger.debug(f"WAF实例获取异常详情", exc_info=True)

        return instances
        
    def get_waf_domains(self) -> List[Dict[str, Any]]:
        """
        获取WAF防护域名信息

        Returns:
            List[Dict[str, Any]]: WAF防护域名列表
        """
        logger.info("获取WAF防护域名信息")
        domains = []

        # 检查SDK是否可用
        if not self.has_waf_sdk or not self.waf_client:
            logger.warning("缺少aliyunsdkwaf_openapi SDK，无法获取WAF防护域名信息")
            return domains

        try:
            # 获取WAF防护域名
            from aliyunsdkwaf_openapi.request.v20190910 import DescribeDomainListRequest
            
            # 首先获取WAF实例信息
            waf_instances = self.get_waf_instances()
            if not waf_instances:
                logger.warning("没有找到WAF实例，无法获取防护域名信息")
                return domains
            
            # 调试信息：打印第一个WAF实例的详细信息
            logger.debug(f"WAF实例信息: {waf_instances[0]}")
            
            instance_id = waf_instances[0].get('instance_id')
            if not instance_id:
                # 检查PayType来判断WAF实例状态
                pay_type = waf_instances[0].get('pay_type')
                if pay_type == 0:
                    logger.info("检测到WAF使用按量付费模式，但没有激活的实例ID")
                    logger.info("这通常表示账户支持WAF但尚未创建实例，或使用的是免费版本")
                else:
                    logger.warning(f"无法获取WAF实例ID，WAF实例信息: {waf_instances[0]}")
                
                logger.info("由于WAF域名列表API要求实例ID为必需参数，跳过域名获取")
                return domains
            
            request = DescribeDomainListRequest.DescribeDomainListRequest()
            request.set_accept_format('json')
            request.set_PageSize(10)
            request.set_PageNumber(1)
            request.set_InstanceId(instance_id)  # WAF API需要实例ID
            
            response = self.waf_client.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            # 处理WAF防护域名数据
            for domain in response_dict.get('DomainList', []):
                domain_info = {
                    'domain': domain.get('Domain'),
                    'instance_id': domain.get('InstanceId'),
                    'cname': domain.get('Cname'),
                    'version': domain.get('Version'),
                    'region': domain.get('Region'),
                    'source_ips': domain.get('SourceIps', []),
                    'protocols': domain.get('Protocols', []),
                    'http_port': domain.get('HttpPort', []),
                    'https_port': domain.get('HttpsPort', []),
                    'load_balancing': domain.get('LoadBalancing'),
                    'http_to_user_ip': domain.get('HttpToUserIp'),
                    'status': domain.get('Status'),
                }
                domains.append(domain_info)
                
            # 处理分页
            total_count = response_dict.get('TotalCount', 0)
            page_size = response_dict.get('PageSize', 10)
            current_page = 1
            
            while total_count > current_page * page_size:
                current_page += 1
                
                request = DescribeDomainListRequest.DescribeDomainListRequest()
                request.set_accept_format('json')
                request.set_PageSize(page_size)
                request.set_PageNumber(current_page)
                request.set_InstanceId(instance_id)  # WAF API需要实例ID
                
                response = self.waf_client.do_action_with_exception(request)
                response_dict = self.session.parse_response(response)
                
                # 处理WAF防护域名数据
                for domain in response_dict.get('DomainList', []):
                    domain_info = {
                        'domain': domain.get('Domain'),
                        'instance_id': domain.get('InstanceId'),
                        'cname': domain.get('Cname'),
                        'version': domain.get('Version'),
                        'region': domain.get('Region'),
                        'source_ips': domain.get('SourceIps', []),
                        'protocols': domain.get('Protocols', []),
                        'http_port': domain.get('HttpPort', []),
                        'https_port': domain.get('HttpsPort', []),
                        'load_balancing': domain.get('LoadBalancing'),
                        'http_to_user_ip': domain.get('HttpToUserIp'),
                        'status': domain.get('Status'),
                    }
                    domains.append(domain_info)
                    
        except ImportError:
            logger.error("无法导入aliyunsdkwaf_openapi模块，请安装相应的SDK")
        except Exception as e:
            logger.error(f"获取WAF防护域名信息失败: {str(e)}")

        return domains

    def get_ddos_instances(self) -> List[Dict[str, Any]]:
        """
        获取DDoS高防实例信息
        注意：DDoS高防服务仅在cn-hangzhou区域可用

        Returns:
            List[Dict[str, Any]]: DDoS高防实例列表
        """
        logger.info("获取DDoS高防实例信息")
        instances = []

        # 检查SDK是否可用
        if not self.has_ddos_sdk or not self.ddos_client:
            logger.warning("缺少aliyunsdkddoscoo SDK，无法获取DDoS高防实例信息")
            return instances

        # 检查区域支持性
        current_region = getattr(self.session, 'region_id', 'cn-hangzhou')
        supported_regions = ['cn-hangzhou']  # DDoS高防仅在杭州区域可用
        
        if current_region not in supported_regions:
            logger.warning(f"DDoS高防服务在当前区域 {current_region} 不可用，仅在以下区域可用: {supported_regions}")
            logger.info("跳过DDoS高防实例获取，因为当前区域不支持此服务")
            return instances

        try:
            # 获取DDoS高防实例
            from aliyunsdkddoscoo.request.v20200101 import DescribeInstancesRequest
            
            request = DescribeInstancesRequest.DescribeInstancesRequest()
            request.set_accept_format('json')
            request.set_PageSize(10)
            request.set_PageNumber(1)
            
            # 设置连接超时
            if hasattr(request, 'set_connect_timeout'):
                request.set_connect_timeout(30)  # 30秒连接超时
            if hasattr(request, 'set_read_timeout'):
                request.set_read_timeout(60)  # 60秒读取超时
            
            # 手动设置正确的域名和协议
            if hasattr(request, 'set_domain'):
                # DDoS高防服务只在杭州区域可用，强制使用杭州端点
                correct_domain = "ddoscoo.cn-hangzhou.aliyuncs.com"
                logger.info(f"设置DDoS高防域名: {correct_domain}")
                request.set_domain(correct_domain)
            
            # 确保使用HTTPS协议
            if hasattr(request, 'set_protocol_type'):
                request.set_protocol_type('https')
                logger.info("设置DDoS高防请求使用HTTPS协议")
            
            response = self.ddos_client.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            # 处理DDoS高防实例数据
            for instance in response_dict.get('Instances', []):
                instance_info = {
                    'instance_id': instance.get('InstanceId'),
                    'remark': instance.get('Remark'),
                    'expire_time': instance.get('ExpireTime'),
                    'domain': instance.get('Domain'),
                    'status': instance.get('Status'),
                    'edition': instance.get('Edition'),
                }
                instances.append(instance_info)
                
            # 处理分页
            total_count = response_dict.get('TotalCount', 0)
            page_size = response_dict.get('PageSize', 10)
            current_page = 1
            
            while total_count > current_page * page_size:
                current_page += 1
                
                request = DescribeInstancesRequest.DescribeInstancesRequest()
                request.set_accept_format('json')
                request.set_PageSize(page_size)
                request.set_PageNumber(current_page)
                
                # 手动设置正确的域名和协议
                if hasattr(request, 'set_domain'):
                    # DDoS高防服务只在杭州区域可用，强制使用杭州端点
                    correct_domain = "ddoscoo.cn-hangzhou.aliyuncs.com"
                    request.set_domain(correct_domain)
                
                # 确保使用HTTPS协议
                if hasattr(request, 'set_protocol_type'):
                    request.set_protocol_type('https')
                
                response = self.ddos_client.do_action_with_exception(request)
                response_dict = self.session.parse_response(response)
                
                # 处理DDoS高防实例数据
                for instance in response_dict.get('Instances', []):
                    instance_info = {
                        'instance_id': instance.get('InstanceId'),
                        'remark': instance.get('Remark'),
                        'expire_time': instance.get('ExpireTime'),
                        'domain': instance.get('Domain'),
                        'status': instance.get('Status'),
                        'edition': instance.get('Edition'),
                    }
                    instances.append(instance_info)
                    
        except ImportError:
            logger.error("无法导入aliyunsdkddoscoo模块，请安装相应的SDK")
        except Exception as e:
            logger.error(f"获取DDoS高防实例信息失败: {str(e)}")

        return instances

    def get_all_security_assets(self) -> Dict[str, Any]:
        """
        获取所有安全资源

        Returns:
            Dict[str, Any]: 所有安全资源
        """
        logger.info("获取所有阿里云安全资源")
        
        # 检查各SDK是否都缺失
        if not any([self.has_sas_sdk, self.has_waf_sdk, self.has_ddos_sdk]):
            logger.warning("缺少所有安全相关SDK，无法获取安全资源")
            return {
                'error': "缺少安全相关SDK，请使用pip安装以下包:\n"
                         "- 云安全中心: pip install aliyun-python-sdk-sas\n"
                         "- WAF: pip install aliyun-python-sdk-waf-openapi\n"
                         "- DDoS高防: pip install aliyun-python-sdk-ddoscoo",
                'status': 'sdk_missing'
            }
        
        # 获取各类安全资源
        # security_center = self.get_security_center_assets() if self.has_sas_sdk else {'error': '缺少aliyunsdksas SDK'}
        waf_instances = self.get_waf_instances() if self.has_waf_sdk else []
        waf_domains = self.get_waf_domains() if self.has_waf_sdk else []
        ddos_instances = self.get_ddos_instances() if self.has_ddos_sdk else []
        
        # 组织返回结果
        security_assets = {
            # 'security_center': security_center,
            'waf': {
                'instances': waf_instances,
                'domains': waf_domains,
                'status': 'available' if self.has_waf_sdk else 'sdk_missing'
            },
            'ddos': {
                'instances': ddos_instances,
                'status': 'available' if self.has_ddos_sdk else 'sdk_missing'
            }
        }
        
        # 日志中提供更具体的可用信息
        sas_status = "可用" if self.has_sas_sdk else "SDK缺失"
        waf_status = "可用" if self.has_waf_sdk else "SDK缺失"
        ddos_status = "可用" if self.has_ddos_sdk else "SDK缺失"
        
        logger.info(f"已获取安全资源 - 云安全中心: {sas_status}，WAF: {waf_status}({len(waf_instances)} 个实例, {len(waf_domains)} 个域名)，DDoS高防: {ddos_status}({len(ddos_instances)} 个实例)")
        return security_assets