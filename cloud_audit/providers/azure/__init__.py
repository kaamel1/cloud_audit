"""
Azure Cloud Provider Implementation
"""
from typing import Dict, Any, Optional
from ...base import CloudProvider, CloudSession, CloudAuditor, CloudAuditorFactory, CloudAuthenticator
from .session import AzureSession


class AzureProvider(CloudProvider):
    """Azure cloud provider implementation"""

    @property
    def name(self) -> str:
        return "azure"


class AzureCloudSession(CloudSession):
    """Azure会话包装器，实现CloudSession接口"""
    
    def __init__(self, azure_session: AzureSession):
        self._session = azure_session
    
    def get_client(self, service_name: str):
        """Get a client for the specified service"""
        return self._session.get_client(service_name)
    
    def get_account_id(self) -> str:
        """Get the current subscription ID"""
        return self._session.get_subscription_id()
    
    def get_enabled_regions(self) -> list:
        """Get the available regions for Azure"""
        return self._session.get_regions()
    
    @property
    def azure_session(self) -> AzureSession:
        """Get the underlying Azure session"""
        return self._session


class AzureAuthenticator(CloudAuthenticator):
    """Azure authentication implementation"""

    def authenticate(self, **kwargs) -> CloudSession:
        """
        Authenticate with Azure using provided credentials or profile.
        
        Args:
            **kwargs: Authentication parameters
                - subscription_id: Azure订阅ID
                - tenant_id: Azure租户ID (可选，用于服务主体认证)
                - client_id: Azure应用程序ID (可选，用于服务主体认证)
                - client_secret: Azure应用程序密钥 (可选，用于服务主体认证)
                - use_cli: 是否使用Azure CLI认证 (默认True)
                - use_msi: 是否使用托管服务标识认证 (默认False)
        
        Returns:
            AzureCloudSession: Authenticated Azure session
        """
        subscription_id = kwargs.get('subscription_id')
        tenant_id = kwargs.get('tenant_id')
        client_id = kwargs.get('client_id')
        client_secret = kwargs.get('client_secret')
        use_cli = kwargs.get('use_cli', True)
        use_msi = kwargs.get('use_msi', False)

        if not subscription_id:
            raise ValueError("subscription_id is required for Azure authentication")

        azure_session = AzureSession(
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            use_cli=use_cli,
            use_msi=use_msi
        )
        
        return AzureCloudSession(azure_session)

    def switch_role(self, session: CloudSession, role_arn: str, **kwargs) -> CloudSession:
        """
        Switch to a different Azure subscription or role.
        
        Args:
            session: Current Azure session
            role_arn: Azure subscription ID to switch to (Azure doesn't use ARN format)
            **kwargs: Additional parameters
                - tenant_id: Target tenant ID (optional)
        
        Returns:
            AzureCloudSession: New session with different subscription
        """
        if not isinstance(session, AzureCloudSession):
            raise ValueError("Session must be an AzureCloudSession instance")
            
        # 在Azure中，role_arn实际上是subscription_id
        new_subscription_id = role_arn
        tenant_id = kwargs.get('tenant_id')
        
        try:
            # 创建新的会话使用不同的订阅ID
            new_azure_session = AzureSession(
                subscription_id=new_subscription_id,
                tenant_id=tenant_id or session.azure_session.tenant_id,
                client_id=session.azure_session.client_id,
                client_secret=session.azure_session.client_secret,
                use_cli=session.azure_session.use_cli,
                use_msi=session.azure_session.use_msi
            )
            
            return AzureCloudSession(new_azure_session)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"切换Azure订阅失败: {str(e)}")
            raise


class AzureAuditorFactory(CloudAuditorFactory):
    """Azure auditor factory"""

    def create_session(self, **kwargs) -> CloudSession:
        """Create an Azure session"""
        authenticator = AzureAuthenticator()
        return authenticator.authenticate(**kwargs)

    def create_auditor(self, session: CloudSession, output_dir: str = "output") -> CloudAuditor:
        """Create an Azure auditor"""
        # 确保会话是 AzureCloudSession 实例
        if not isinstance(session, AzureCloudSession):
            raise ValueError("Session must be an AzureCloudSession instance")
        
        from .auditor import AzureAuditor
        return AzureAuditor(session.azure_session, output_dir)


# 导出主要类
__all__ = [
    'AzureProvider',
    'AzureCloudSession', 
    'AzureAuthenticator',
    'AzureAuditorFactory'
] 