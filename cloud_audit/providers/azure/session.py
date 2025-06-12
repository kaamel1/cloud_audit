"""Azure会话管理模块，负责处理Azure SDK的认证和客户端创建"""
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class AzureSession:
    """Azure会话管理类"""

    def __init__(self, subscription_id: str, tenant_id: Optional[str] = None, 
                 client_id: Optional[str] = None, client_secret: Optional[str] = None,
                 use_cli: bool = True, use_msi: bool = False):
        """
        初始化Azure会话

        Args:
            subscription_id: Azure订阅ID
            tenant_id: Azure租户ID (可选，用于服务主体认证)
            client_id: Azure应用程序ID (可选，用于服务主体认证)
            client_secret: Azure应用程序密钥 (可选，用于服务主体认证)
            use_cli: 是否使用Azure CLI认证 (默认True)
            use_msi: 是否使用托管服务标识认证 (默认False)
        """
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_cli = use_cli
        self.use_msi = use_msi
        self.clients = {}
        self._credential = None
        
        # 初始化认证凭据
        self._initialize_credential()
    
    def _initialize_credential(self):
        """初始化Azure认证凭据"""
        try:
            from azure.identity import (
                DefaultAzureCredential, 
                ClientSecretCredential,
                AzureCliCredential,
                ManagedIdentityCredential
            )
            
            if self.client_id and self.client_secret and self.tenant_id:
                # 使用服务主体认证
                self._credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
                logger.info("使用服务主体认证初始化Azure凭据")
            elif self.use_msi:
                # 使用托管服务标识认证
                self._credential = ManagedIdentityCredential()
                logger.info("使用托管服务标识认证初始化Azure凭据")
            elif self.use_cli:
                # 使用Azure CLI认证
                self._credential = AzureCliCredential()
                logger.info("使用Azure CLI认证初始化Azure凭据")
            else:
                # 使用默认认证链
                self._credential = DefaultAzureCredential()
                logger.info("使用默认认证链初始化Azure凭据")
                
        except ImportError as e:
            logger.error(f"导入Azure认证模块失败: {str(e)}")
            logger.error("请安装Azure SDK: pip install azure-identity azure-mgmt-resource azure-mgmt-compute azure-mgmt-network azure-mgmt-storage")
            raise
        except Exception as e:
            logger.error(f"初始化Azure认证凭据失败: {str(e)}")
            raise
    
    def get_client(self, service_name: str) -> Any:
        """
        获取指定服务的客户端

        Args:
            service_name: 服务名称，如'resource', 'compute', 'network', 'storage'等

        Returns:
            Any: Azure服务客户端
        """
        if service_name not in self.clients:
            self.clients[service_name] = self._create_client(service_name)
        return self.clients[service_name]
    
    def _create_client(self, service_name: str) -> Any:
        """
        创建Azure服务客户端

        Args:
            service_name: 服务名称

        Returns:
            Any: Azure服务客户端
        """
        try:
            client_mapping = {
                'resource': ('azure.mgmt.resource', 'ResourceManagementClient'),
                'compute': ('azure.mgmt.compute', 'ComputeManagementClient'),
                'network': ('azure.mgmt.network', 'NetworkManagementClient'),
                'storage': ('azure.mgmt.storage', 'StorageManagementClient'),
                'monitor': ('azure.mgmt.monitor', 'MonitorManagementClient'),
                'keyvault': ('azure.mgmt.keyvault', 'KeyVaultManagementClient'),
                'sql': ('azure.mgmt.sql', 'SqlManagementClient'),
                'web': ('azure.mgmt.web', 'WebSiteManagementClient'),
                'authorization': ('azure.mgmt.authorization', 'AuthorizationManagementClient'),
                'security': ('azure.mgmt.security', 'SecurityCenter'),
                'subscription': ('azure.mgmt.subscription', 'SubscriptionClient'),
            }
            
            if service_name not in client_mapping:
                raise ValueError(f"不支持的Azure服务: {service_name}")
            
            module_name, class_name = client_mapping[service_name]
            
            # 动态导入Azure SDK模块
            import importlib
            module = importlib.import_module(module_name)
            client_class = getattr(module, class_name)
            
            # 创建客户端
            if service_name == 'subscription':
                # SubscriptionClient不需要subscription_id参数
                client = client_class(credential=self._credential)
            else:
                client = client_class(
                    credential=self._credential,
                    subscription_id=self.subscription_id
                )
            
            logger.info(f"成功创建Azure {service_name} 客户端")
            return client
            
        except ImportError as e:
            logger.error(f"导入Azure SDK模块失败 ({service_name}): {str(e)}")
            logger.error(f"请安装相应的Azure SDK包: pip install {module_name.replace('.', '-')}")
            raise
        except Exception as e:
            logger.error(f"创建Azure {service_name} 客户端失败: {str(e)}")
            raise
    
    def get_subscription_id(self) -> str:
        """
        获取当前订阅ID
        
        Returns:
            str: 订阅ID
        """
        return self.subscription_id
    
    def get_regions(self) -> List[str]:
        """
        获取Azure可用区域列表
        
        Returns:
            List[str]: 区域列表
        """
        try:
            subscription_client = self.get_client('subscription')
            locations = []
            
            # 获取订阅的可用位置
            for location in subscription_client.subscriptions.list_locations(self.subscription_id):
                locations.append(location.name)
            
            logger.info(f"获取到 {len(locations)} 个Azure区域")
            return locations
            
        except Exception as e:
            logger.warning(f"获取Azure区域列表失败: {str(e)}")
            # 返回常用的Azure区域作为备选
            return [
                'eastus', 'eastus2', 'westus', 'westus2', 'westus3',
                'centralus', 'northcentralus', 'southcentralus', 'westcentralus',
                'eastasia', 'southeastasia', 'japaneast', 'japanwest',
                'australiaeast', 'australiasoutheast', 'australiacentral',
                'brazilsouth', 'southafricanorth', 'southafricawest',
                'northeurope', 'westeurope', 'francecentral', 'francesouth',
                'germanywestcentral', 'norwayeast', 'switzerlandnorth',
                'uksouth', 'ukwest', 'uaenorth', 'uaecentral',
                'canadacentral', 'canadaeast', 'koreacentral', 'koreasouth',
                'centralindia', 'southindia', 'westindia'
            ]
    
    def test_connection(self) -> bool:
        """
        测试Azure连接是否正常
        
        Returns:
            bool: 连接是否成功
        """
        try:
            # 尝试获取订阅信息来测试连接
            subscription_client = self.get_client('subscription')
            subscription = subscription_client.subscriptions.get(self.subscription_id)
            
            # 安全地获取display_name属性
            display_name = getattr(subscription, 'display_name', 'Unknown')
            logger.info(f"Azure连接测试成功，订阅: {display_name}")
            return True
            
        except Exception as e:
            logger.error(f"Azure连接测试失败: {str(e)}")
            return False
    
    def get_subscription_info(self) -> Dict[str, Any]:
        """
        获取订阅详细信息
        
        Returns:
            Dict[str, Any]: 订阅信息
        """
        try:
            subscription_client = self.get_client('subscription')
            subscription = subscription_client.subscriptions.get(self.subscription_id)
            
            # 安全地获取属性，处理不同版本的Azure SDK
            subscription_info = {
                'subscription_id': getattr(subscription, 'subscription_id', self.subscription_id),
                'display_name': getattr(subscription, 'display_name', 'Unknown'),
                'state': getattr(subscription, 'state', 'Unknown'),
                'tenant_id': getattr(subscription, 'tenant_id', None) or self.tenant_id or 'Unknown',
                'authorization_source': getattr(subscription, 'authorization_source', 'Unknown')
            }
            
            logger.info(f"成功获取订阅信息: {subscription_info['display_name']}")
            return subscription_info
            
        except Exception as e:
            logger.error(f"获取订阅信息失败: {str(e)}")
            return {
                'subscription_id': self.subscription_id,
                'display_name': 'Unknown',
                'state': 'Unknown',
                'tenant_id': self.tenant_id or 'Unknown',
                'authorization_source': 'Unknown'
            } 