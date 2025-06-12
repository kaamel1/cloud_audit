"""
QCloud (Tencent Cloud) Provider Implementation
"""
from typing import Dict, Any
from ...base import CloudProvider, CloudSession, CloudAuditor, CloudAuditorFactory, CloudAuthenticator


class QCloudProvider(CloudProvider):
    """腾讯云provider实现"""

    @property
    def name(self) -> str:
        return "qcloud"


class QCloudAuthenticator(CloudAuthenticator):
    """腾讯云认证实现"""

    def authenticate(self, **kwargs) -> CloudSession:
        """
        使用提供的凭证认证腾讯云
        
        Args:
            **kwargs: 认证参数
                - secret_id: 腾讯云SecretId
                - secret_key: 腾讯云SecretKey
                - token: 临时访问凭证Token (可选)
                - region: 腾讯云地域 (可选)
        
        Returns:
            QCloudSession: 已认证的腾讯云会话
        """
        try:
            from tencentcloud.common import credential
            from .session import QCloudSession
        except ImportError:
            raise ImportError("请安装腾讯云SDK: pip install tencentcloud-sdk-python")
        
        secret_id = kwargs.get('secret_id')
        secret_key = kwargs.get('secret_key')
        token = kwargs.get('token')
        region = kwargs.get('region', 'ap-beijing')  # 默认北京区域

        if secret_id and secret_key:
            if token:
                # 使用临时凭证
                cred = credential.Credential(secret_id, secret_key, token)
            else:
                # 使用永久凭证
                cred = credential.Credential(secret_id, secret_key)
            
            return QCloudSession(cred, region)
        else:
            # 尝试使用环境变量凭证
            try:
                cred = credential.EnvironmentVariableCredential().get_credential()
                return QCloudSession(cred, region)
            except Exception:
                # 回退到默认凭证提供链
                cred = credential.DefaultCredentialProvider().get_credential()
                return QCloudSession(cred, region)

    def switch_role(self, session: CloudSession, role_arn: str, **kwargs) -> CloudSession:
        """
        使用STS临时凭证切换角色
        
        Args:
            session: 当前腾讯云会话
            role_arn: 要切换的角色ARN (腾讯云中为RoleArn)
            **kwargs: 额外参数
                - role_session_name: 角色会话名称
                - duration_seconds: 会话持续时间(秒)
                - policy: 会话策略(可选)
        
        Returns:
            QCloudSession: 新的会话实例
        """
        from .session import QCloudSession
        
        if not isinstance(session, QCloudSession):
            raise ValueError("Session must be a QCloudSession instance")

        role_session_name = kwargs.get('role_session_name', 'CloudAudit')
        duration_seconds = kwargs.get('duration_seconds', 3600)
        policy = kwargs.get('policy')

        # 使用STS获取临时凭证
        new_session = session.assume_role(
            role_arn=role_arn,
            session_name=role_session_name,
            duration_seconds=duration_seconds,
            policy=policy
        )
        
        return new_session


class QCloudAuditorFactory(CloudAuditorFactory):
    """创建腾讯云审计器的工厂类"""

    def create_session(self, **kwargs) -> CloudSession:
        authenticator = QCloudAuthenticator()
        session = authenticator.authenticate(**kwargs)

        if role_arn := kwargs.get('role_arn'):
            # 创建一个新的kwargs字典，不包含role_arn
            role_kwargs = {k: v for k, v in kwargs.items() if k != 'role_arn'}
            session = authenticator.switch_role(session, role_arn, **role_kwargs)

        return session

    def create_auditor(self, session: CloudSession, output_dir: str = "output") -> CloudAuditor:
        # 确保会话是 QCloudSession 实例
        from .session import QCloudSession
        
        if not isinstance(session, QCloudSession):
            raise ValueError("Session must be a QCloudSession instance")

        from .auditor import QCloudAuditor
        return QCloudAuditor(session, output_dir)


# 导入session和auditor类以便导出
from .session import QCloudSession
from .auditor import QCloudAuditor

__all__ = [
    'QCloudProvider',
    'QCloudSession',
    'QCloudAuthenticator',
    'QCloudAuditor',
    'QCloudAuditorFactory',
] 