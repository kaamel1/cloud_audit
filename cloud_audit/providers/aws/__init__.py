"""
AWS Cloud Provider Implementation
"""
from typing import Dict, Any
import boto3
from ...base import CloudProvider, CloudSession, CloudAuditor, CloudAuditorFactory, CloudAuthenticator
from .session import AWSSession

class AWSProvider(CloudProvider):
    """AWS cloud provider implementation"""

    @property
    def name(self) -> str:
        return "aws"


class AWSAuthenticator(CloudAuthenticator):
    """AWS authentication implementation"""

    def authenticate(self, **kwargs) -> CloudSession:
        """
        Authenticate with AWS using provided credentials or profile.
        
        Args:
            **kwargs: Authentication parameters
                - profile: AWS profile name
                - access_key_id: AWS access key ID
                - secret_access_key: AWS secret access key
                - session_token: AWS session token (optional)
                - region: AWS region (optional)
        
        Returns:
            AWSSession: Authenticated AWS session
        """
        profile = kwargs.get('profile')
        access_key = kwargs.get('access_key_id')
        secret_key = kwargs.get('secret_access_key')
        session_token = kwargs.get('session_token')
        region = kwargs.get('region')

        if profile:
            # 使用profile时，同时支持指定region
            session_kwargs = {'profile_name': profile}
            if region:
                session_kwargs['region_name'] = region
            session = boto3.Session(**session_kwargs)
            return AWSSession(session)
        elif access_key and secret_key:
            return AWSSession.create_from_credentials(
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token,
                region=region
            )
        else:
            # 默认会话，如果指定了region也应该使用
            session_kwargs = {}
            if region:
                session_kwargs['region_name'] = region
            session = boto3.Session(**session_kwargs)
            return AWSSession(session)

    def switch_role(self, session: CloudSession, role_arn: str, **kwargs) -> CloudSession:
        """
        Switch to a different AWS role using the provided session.
        
        Args:
            session: Current AWS session
            role_arn: ARN of the role to assume
            **kwargs: Additional parameters
                - role_session_name: Name for the role session (default: CloudAudit)
                - external_id: External ID for additional security (optional)
                - duration_seconds: Duration of the session in seconds (default: 3600)
                - region: AWS region (optional, 如果提供则覆盖当前会话的region)
        
        Returns:
            AWSSession: New session with assumed role credentials
        """
        if not isinstance(session, AWSSession):
            raise ValueError("Session must be an AWSSession instance")

        role_session_name = kwargs.get('role_session_name', 'CloudAudit')
        external_id = kwargs.get('external_id')
        duration_seconds = kwargs.get('duration_seconds', 3600)

        # 获取角色切换后的会话
        new_session = session.assume_role(
            role_arn=role_arn,
            session_name=role_session_name,
            external_id=external_id,
            duration_seconds=duration_seconds
        )
        
        # 如果提供了region参数，并且与当前不同，创建新的会话
        if 'region' in kwargs and kwargs['region'] != new_session.boto3_session.region_name:
            region = kwargs['region']
            credentials = new_session.boto3_session.get_credentials()
            
            return AWSSession.create_from_credentials(
                access_key=credentials.access_key,
                secret_key=credentials.secret_key,
                session_token=credentials.token,
                region=region
            )
            
        return new_session


class AWSAuditorFactory(CloudAuditorFactory):
    """Factory for creating AWS auditors"""

    def create_session(self, **kwargs) -> CloudSession:
        authenticator = AWSAuthenticator()
        session = authenticator.authenticate(**kwargs)

        if role_arn := kwargs.get('role_arn'):
            # 创建一个新的kwargs字典，不包含role_arn
            role_kwargs = {k: v for k, v in kwargs.items() if k != 'role_arn'}
            session = authenticator.switch_role(session, role_arn, **role_kwargs)

        return session

    def create_auditor(self, session: CloudSession, output_dir: str = "output") -> CloudAuditor:
        # 确保会话是 AWSSession 实例
        if not isinstance(session, AWSSession):
            # 如果会话是 boto3.Session，尝试包装它
            if isinstance(session, boto3.Session):
                session = AWSSession(session)
            else:
                raise ValueError("Session must be an AWSSession or boto3.Session instance")

        from .auditor import AWSAuditor
        return AWSAuditor(session, output_dir)


# 导入session和auditor类以便导出
from .auditor import AWSAuditor

__all__ = [
    'AWSProvider',
    'AWSSession',
    'AWSAuthenticator',
    'AWSAuditor',
    'AWSAuditorFactory',
]
