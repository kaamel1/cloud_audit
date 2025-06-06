"""阿里云会话管理模块，负责处理阿里云SDK的认证和客户端创建"""
import logging
import importlib
import json
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class MockRequest:
    """
    模拟请求对象，用于处理不可用SDK的情况
    
    当特定的SDK不可用或API不存在时，返回这个对象以便程序继续运行
    """
    
    def __init__(self, service_name: str, action: str):
        """
        初始化模拟请求对象
        
        Args:
            service_name: 服务名称
            action: API操作名称
        """
        self.service_name = service_name
        self.action = action
        self.params = {}
    
    def set_query_param(self, key: str, value: Any):
        """
        设置查询参数，模拟正常请求对象
        
        Args:
            key: 参数名
            value: 参数值
        """
        self.params[key] = value
        return self
    
    def set_accept_format(self, format_type: str):
        """
        设置接受格式，模拟正常请求对象
        
        Args:
            format_type: 格式类型，如'json'
        """
        self.params['format'] = format_type
        return self
        
    def set_domain(self, domain: str):
        """
        设置域名，模拟正常请求对象
        
        Args:
            domain: 域名
        """
        self.domain = domain
        return self
    
    def __str__(self) -> str:
        """返回请求的字符串表示"""
        return f"MockRequest(service={self.service_name}, action={self.action})"


class AliyunSession:
    """阿里云会话管理类"""

    def __init__(self, access_key_id: str, access_key_secret: str, region_id: str = "cn-hangzhou", security_token: Optional[str] = None):
        """
        初始化阿里云会话

        Args:
            access_key_id: 阿里云访问密钥ID
            access_key_secret: 阿里云访问密钥Secret
            region_id: 阿里云区域ID，默认为杭州区域
            security_token: 安全令牌，用于临时凭证（可选）
        """
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.region_id = region_id
        self.security_token = security_token
        self.clients = {}
    
    def get_client(self, service_name: str) -> Any:
        """
        获取指定服务的客户端

        Args:
            service_name: 服务名称，如'ecs', 'vpc', 'oss'等

        Returns:
            Any: 阿里云服务客户端
        """
        if service_name not in self.clients:
            self.clients[service_name] = self._create_client(service_name)
        return self.clients[service_name]
    
    def _create_client(self, service_name: str) -> Any:
        """
        创建阿里云服务客户端

        Args:
            service_name: 服务名称

        Returns:
            Any: 阿里云服务客户端
        """
        try:
            # 动态导入阿里云SDK模块
            module_name = f"aliyunsdkcore.client"
            core_module = importlib.import_module(module_name)
            
            # 根据阿里云官方文档，当有SecurityToken时使用特殊的凭证类型
            if self.security_token:
                try:
                    # 尝试使用StsTokenCredential方式创建客户端
                    auth_module = importlib.import_module("aliyunsdkcore.auth.credentials")
                    
                    # 创建STS Token凭证对象
                    sts_credential = auth_module.StsTokenCredential(
                        sts_access_key_id=self.access_key_id,
                        sts_access_key_secret=self.access_key_secret,
                        sts_token=self.security_token
                    )
                    
                    # 使用凭证对象创建客户端
                    # 注意: core-v3版本中应使用AcsClient的新构造方式
                    try:
                        # 首先尝试新的构造方式
                        client = core_module.AcsClient(
                            region_id=self.region_id,
                            credential=sts_credential
                        )
                        logger.info(f"成功创建阿里云 {service_name} 客户端 (使用core-v3版本的StsTokenCredential)")
                    except TypeError:
                        # 如果新构造方式失败，回退到旧构造方式
                        logger.warning(f"新版AcsClient构造失败，尝试旧版构造方式")
                        client = core_module.AcsClient(
                            self.access_key_id,
                            self.access_key_secret,
                            self.region_id,
                            security_token=self.security_token
                        )
                        logger.info(f"成功创建阿里云 {service_name} 客户端 (使用旧版构造方式，SecurityToken: {self.security_token[:10]}...)")
                    
                except ImportError:
                    # 如果StsTokenCredential不可用，回退到直接传参方式
                    logger.warning("StsTokenCredential不可用，使用直接传参方式")
                    client = core_module.AcsClient(
                        self.access_key_id,
                        self.access_key_secret,
                        self.region_id,
                        security_token=self.security_token
                    )
                    logger.info(f"成功创建阿里云 {service_name} 客户端 (使用直接传参，SecurityToken: {self.security_token[:10]}...)")
                    
            else:
                # 使用永久凭证创建客户端
                client = core_module.AcsClient(
                    self.access_key_id,
                    self.access_key_secret,
                    self.region_id
                )
                logger.info(f"成功创建阿里云 {service_name} 客户端 (永久凭证)")
            
            # 特殊处理一些服务的域名问题
            if service_name == 'ddoscoo':
                # DDoS高防服务的域名格式修复
                self._fix_ddos_endpoint(client)
            
            return client
        except ImportError as e:
            logger.error(f"导入阿里云SDK模块失败: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"创建阿里云 {service_name} 客户端失败: {str(e)}")
            raise
    
    def _fix_ddos_endpoint(self, client):
        """
        修复DDoS高防服务的域名和协议问题
        注意：DDoS高防服务仅在cn-hangzhou区域可用
        
        Args:
            client: AcsClient实例
        """
        try:
            # DDoS高防服务只在杭州区域可用，强制使用杭州端点
            product_domain = "ddoscoo.cn-hangzhou.aliyuncs.com"
            logger.info(f"设置DDoS高防域名: {product_domain} (强制使用杭州区域)")
            
            # 通过反射修改客户端的域名构建逻辑
            if hasattr(client, '_endpoint_resolver'):
                setattr(client, '_endpoint', product_domain)
                logger.info(f"成功设置DDoS高防域名为: {product_domain}")
            
            # 确保客户端使用HTTPS协议
            if hasattr(client, '_config'):
                client._config['protocol'] = 'https'
                logger.info("设置DDoS高防客户端使用HTTPS协议")
            elif hasattr(client, 'set_protocol_type'):
                client.set_protocol_type('https')
                logger.info("设置DDoS高防客户端使用HTTPS协议")
                
        except Exception as e:
            logger.warning(f"设置DDoS高防域名和协议失败，可能导致API调用问题: {str(e)}")
    
    def create_request(self, service_name: str, action: str) -> Any:
        """
        创建阿里云API请求对象
        
        Args:
            service_name: 服务名称，如'ecs', 'vpc', 'ram'等
            action: API操作名称，如'DescribeInstances'等
            
        Returns:
            Any: 阿里云请求对象
        """
        try:
            # 根据服务名称和操作名称动态导入对应的请求类
            # 这里需要根据阿里云SDK的包结构来导入
            service_module_map = {
                'ecs': 'aliyunsdkecs.request.v20140526',
                'vpc': 'aliyunsdkvpc.request.v20160428',
                'ram': 'aliyunsdkram.request.v20150501',
                'rds': 'aliyunsdkrds.request.v20140815',
                'sts': 'aliyunsdksts.request.v20150401',
                'mongodb': 'aliyunsdkmongodb.request.v20151201',
                'redis': 'aliyunsdkredis.request.v20150101',
                # OSS使用单独的oss2包，不是标准的aliyunsdkoss
                'cbn': 'aliyunsdkcbn.request.v20170912',
                # Express Connect应该使用专用的SDK，不在ECS模块下
                'expressconnect': 'aliyunsdkexpressconnect.request.v20181111',
                # VPN应该使用专用的SDK，不在VPC模块下
                'vpn': 'aliyunsdkvpn.request.v20200409',
                'domain': 'aliyunsdkdomain.request.v20180129',
                'dns': 'aliyunsdkalidns.request.v20150109',
                'cdn': 'aliyunsdkcdn.request.v20180510',
                # 安全评估服务 (SAS)
                'sas': 'aliyunsdksas.request.v20181203',
                # 云监控服务 (CMS)
                'cms': 'aliyunsdkcms.request.v20190101',
            }
            
            # 定义备用API版本映射，当主要版本不可用时尝试这些版本
            alternative_versions = {
                'domain': [
                    'aliyunsdkdomain.request.v20180208',
                    'aliyunsdkdomain.request.v20210325'
                ],
                'dns': [
                    'aliyunsdkalidns.request.v20180208',
                    'aliyunsdkalidns.request.v20190117'
                ],
                'cbn': [
                    'aliyunsdkcbn.request.v20160707',  # 尝试更早的版本
                    'aliyunsdkcbn.request.v20190215',  # 尝试更新的版本
                    'aliyunsdkcbn.request.v20150408'   # 尝试最早的版本
                ]
            }
            
            # 尝试主要版本
            module_name = service_module_map.get(service_name)
            if not module_name:
                raise ValueError(f"不支持的服务: {service_name}")
            
            try:
                # 构造完整的请求类模块路径
                request_class_name = f"{action}Request"
                request_module_path = f"{module_name}.{request_class_name}"
                
                # 首先尝试导入具体的请求类模块
                try:
                    request_module = importlib.import_module(request_module_path)
                    # 从请求类模块中获取请求类
                    request_class = getattr(request_module, request_class_name)
                    request = request_class()
                    request.set_accept_format('json')
                    logger.debug(f"成功从模块 {request_module_path} 创建请求类 {request_class_name}")
                    return request
                except ImportError:
                    # 如果直接导入请求类模块失败，尝试从版本模块中获取
                    version_module = importlib.import_module(module_name)
                    if hasattr(version_module, request_class_name):
                        request_class = getattr(version_module, request_class_name)
                        request = request_class()
                        request.set_accept_format('json')
                        logger.debug(f"成功从版本模块 {module_name} 创建请求类 {request_class_name}")
                        return request
                    else:
                        # 如果主版本中找不到请求类，尝试备用版本
                        if service_name in alternative_versions:
                            for alt_module_name in alternative_versions[service_name]:
                                try:
                                    # 尝试导入备用版本的具体请求类模块
                                    alt_request_module_path = f"{alt_module_name}.{request_class_name}"
                                    try:
                                        alt_request_module = importlib.import_module(alt_request_module_path)
                                        request_class = getattr(alt_request_module, request_class_name)
                                        request = request_class()
                                        request.set_accept_format('json')
                                        logger.info(f"在备用模块 {alt_request_module_path} 中找到请求类 {request_class_name}")
                                        return request
                                    except ImportError:
                                        # 如果直接导入备用请求类模块失败，尝试从备用版本模块中获取
                                        alt_version_module = importlib.import_module(alt_module_name)
                                        if hasattr(alt_version_module, request_class_name):
                                            request_class = getattr(alt_version_module, request_class_name)
                                            request = request_class()
                                            request.set_accept_format('json')
                                            logger.info(f"在备用版本模块 {alt_module_name} 中找到请求类 {request_class_name}")
                                            return request
                                except ImportError:
                                    continue
                        
                        # 如果所有备用版本都不可用，记录错误并返回模拟请求
                        error_msg = f"在模块 {module_name} 中找不到请求类 {request_class_name}"
                        logger.error(f"创建 {service_name} {action} 请求失败: {error_msg}")
                        return MockRequest(service_name, action)
            except ImportError as e:
                logger.error(f"导入服务 {service_name} 的请求模块失败: {str(e)}")
                # 尝试备用版本
                if service_name in alternative_versions:
                    for alt_module_name in alternative_versions[service_name]:
                        try:
                            request_class_name = f"{action}Request"
                            # 尝试导入备用版本的具体请求类模块
                            alt_request_module_path = f"{alt_module_name}.{request_class_name}"
                            try:
                                alt_request_module = importlib.import_module(alt_request_module_path)
                                request_class = getattr(alt_request_module, request_class_name)
                                request = request_class()
                                request.set_accept_format('json')
                                logger.info(f"在备用模块 {alt_request_module_path} 中找到请求类 {request_class_name}")
                                return request
                            except ImportError:
                                # 如果直接导入备用请求类模块失败，尝试从备用版本模块中获取
                                alt_version_module = importlib.import_module(alt_module_name)
                                if hasattr(alt_version_module, request_class_name):
                                    request_class = getattr(alt_version_module, request_class_name)
                                    request = request_class()
                                    request.set_accept_format('json')
                                    logger.info(f"在备用版本模块 {alt_module_name} 中找到请求类 {request_class_name}")
                                    return request
                        except ImportError:
                            continue
                
                # 返回一个模拟的请求对象，以便程序继续运行
                return MockRequest(service_name, action)
        except Exception as e:
            logger.error(f"创建 {service_name} {action} 请求失败: {str(e)}")
            return MockRequest(service_name, action)
    
    def do_action_with_exception(self, request) -> str:
        """
        执行API请求
        
        Args:
            request: API请求对象
            
        Returns:
            str: API响应字符串
        """
        try:
            # 如果是模拟请求对象，返回空响应
            if isinstance(request, MockRequest):
                logger.warning(f"跳过模拟请求: {request.service_name} {request.action}")
                
                # 如果是CBN的DescribeCens请求，返回一个模拟的空响应结构
                if request.service_name == 'cbn' and request.action in ['DescribeCens', 'DescribeCenInstances', 'DescribeCloudEnterpriseNetworks']:
                    return '{"RequestId":"mock-request-id","TotalCount":0,"PageNumber":1,"PageSize":10,"Cens":{"Cen":[]}}'
                
                # 如果是CBN的DescribeCenAttachedChildInstances请求，返回一个模拟的空响应结构
                if request.service_name == 'cbn' and request.action in ['DescribeCenAttachedChildInstances', 'DescribeCenChildInstanceAttachments', 'DescribeChildInstanceAttachments']:
                    return '{"RequestId":"mock-request-id","TotalCount":0,"PageNumber":1,"PageSize":10,"ChildInstances":{"ChildInstance":[]}}'
                
                return '{"error": "service not available"}'
            
            # 获取对应的客户端（根据请求类型推断服务名称）
            client = self._get_client_for_request(request)
            return client.do_action_with_exception(request)
        except Exception as e:
            logger.error(f"执行API请求失败: {str(e)}")
            raise
    
    def parse_response(self, response: str) -> Dict[str, Any]:
        """
        解析API响应
        
        Args:
            response: API响应字符串
            
        Returns:
            Dict[str, Any]: 解析后的响应字典
        """
        try:
            return json.loads(response)
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {str(e)}")
            return {}
    
    def _get_client_for_request(self, request) -> Any:
        """
        根据请求对象获取对应的客户端
        
        Args:
            request: API请求对象
            
        Returns:
            Any: 对应的阿里云客户端
        """
        # 根据请求对象的类名推断服务类型
        class_name = request.__class__.__name__
        module_name = request.__class__.__module__
        
        if 'ecs' in module_name:
            return self.get_client('ecs')
        elif 'vpc' in module_name:
            return self.get_client('vpc')
        elif 'ram' in module_name:
            return self.get_client('ram')
        elif 'rds' in module_name:
            return self.get_client('rds')
        elif 'sts' in module_name:
            return self.get_client('sts')
        elif 'alidns' in module_name:
            return self.get_client('dns')
        elif 'domain' in module_name:
            return self.get_client('domain')
        elif 'cdn' in module_name:
            return self.get_client('cdn')
        elif 'cbn' in module_name:
            return self.get_client('cbn')
        elif 'expressconnect' in module_name:
            return self.get_client('expressconnect')
        elif 'vpn' in module_name:
            return self.get_client('vpn')
        # OSS使用单独的oss2包，所以不通过标准客户端获取
        elif 'mongodb' in module_name:
            return self.get_client('mongodb')
        elif 'redis' in module_name:
            return self.get_client('redis')
        elif 'sas' in module_name:
            return self.get_client('sas')
        elif 'cms' in module_name:
            return self.get_client('cms')
        else:
            # 默认使用通用客户端
            return self.get_client('ecs')
    
    def get_regions(self) -> list:
        """
        获取阿里云可用区域列表

        Returns:
            list: 区域列表
        """
        try:
            # 使用ECS客户端获取区域列表
            from aliyunsdkecs.request.v20140526 import DescribeRegionsRequest
            
            client = self.get_client('ecs')
            request = DescribeRegionsRequest.DescribeRegionsRequest()
            response = client.do_action_with_exception(request)
            
            # 解析响应
            regions_info = json.loads(response)
            return regions_info.get('Regions', {}).get('Region', [])
        except Exception as e:
            logger.error(f"获取阿里云区域列表失败: {str(e)}")
            return []