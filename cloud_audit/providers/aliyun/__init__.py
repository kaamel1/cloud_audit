"""
阿里云Cloud Provider Implementation
"""
from typing import Dict, Any, Optional
from ...base import CloudProvider, CloudSession, CloudAuditor, CloudAuditorFactory, CloudAuthenticator
from .session import AliyunSession


class AliyunProvider(CloudProvider):
    """阿里云cloud provider implementation"""

    @property
    def name(self) -> str:
        return "aliyun"


class AliyunCloudSession(CloudSession):
    """阿里云会话包装器，实现CloudSession接口"""
    
    def __init__(self, aliyun_session: AliyunSession):
        self._session = aliyun_session
    
    def get_client(self, service_name: str):
        """Get a client for the specified service"""
        return self._session.get_client(service_name)
    
    def get_account_id(self) -> str:
        """Get the current account ID"""
        # 阿里云通过STS获取账号信息
        try:
            from aliyunsdksts.request.v20150401 import GetCallerIdentityRequest
            import json
            
            client = self._session.get_client('sts')
            request = GetCallerIdentityRequest.GetCallerIdentityRequest()
            response = client.do_action_with_exception(request)
            
            result = json.loads(response)
            return result.get('AccountId', 'unknown')
        except ImportError:
            # 如果缺少STS SDK，返回一个提示信息而不是错误
            return 'unknown (请安装阿里云STS SDK: pip install aliyun-python-sdk-sts)'
        except Exception as e:
            # 如果无法获取账号ID，返回一个默认值
            return f'unknown (获取失败: {str(e)})'
    
    def get_enabled_regions(self) -> list:
        """Get the available regions for aliyun"""
        return self._session.get_regions()
    
    @property
    def aliyun_session(self) -> AliyunSession:
        """Get the underlying aliyun session"""
        return self._session


class AliyunAuthenticator(CloudAuthenticator):
    """阿里云authentication implementation"""

    def authenticate(self, **kwargs) -> CloudSession:
        """
        Authenticate with Aliyun using provided credentials or profile.
        
        Args:
            **kwargs: Authentication parameters
                - profile: 阿里云配置文件名称 (从~/.aliyun/config读取)
                - access_key_id: 阿里云访问密钥ID
                - access_key_secret: 阿里云访问密钥Secret
                - region_id: 阿里云区域ID (optional, 默认为cn-hangzhou)
        
        Returns:
            AliyunCloudSession: Authenticated Aliyun session
        """
        profile = kwargs.get('profile')
        access_key_id = kwargs.get('access_key_id')
        access_key_secret = kwargs.get('access_key_secret')
        region_id = kwargs.get('region_id', 'cn-hangzhou')

        if profile:
            # 使用配置文件获取凭证
            try:
                import json
                import os
                
                config_path = os.path.expanduser('~/.aliyun/config.json')
                if not os.path.exists(config_path):
                    raise ValueError(f"阿里云配置文件不存在: {config_path}")
                
                with open(config_path, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                
                # 阿里云CLI配置文件格式
                profiles = config_data.get('profiles', [])
                target_profile = None
                
                # 查找指定的profile
                for p in profiles:
                    if p.get('name') == profile:
                        target_profile = p
                        break
                
                if not target_profile:
                    raise ValueError(f"配置文件中未找到profile: {profile}")
                
                access_key_id = target_profile.get('access_key_id')
                access_key_secret = target_profile.get('access_key_secret')
                
                # 从配置文件获取区域（如果有的话）
                if target_profile.get('region_id'):
                    region_id = target_profile.get('region_id')
                    
            except json.JSONDecodeError as e:
                raise ValueError(f"阿里云配置文件格式错误: {str(e)}")
            except Exception as e:
                raise ValueError(f"读取阿里云配置文件失败: {str(e)}")

        if not access_key_id or not access_key_secret:
            raise ValueError("access_key_id and access_key_secret are required for Aliyun authentication")

        aliyun_session = AliyunSession(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region_id
        )
        
        return AliyunCloudSession(aliyun_session)

    def switch_role(self, session: CloudSession, role_arn: str, **kwargs) -> CloudSession:
        """
        Switch to a different Aliyun role using the provided session.
        
        Args:
            session: Current Aliyun session
            role_arn: ARN of the role to assume
            **kwargs: Additional parameters
                - role_session_name: Name for the role session (default: AliyunCloudAuditSession)
                - external_id: External ID for additional security (optional)
                - duration_seconds: Duration of the session in seconds (default: 3600)
                - region_id: Aliyun region ID (optional, 如果提供则覆盖当前会话的region_id)
        
        Returns:
            AliyunCloudSession: New session with assumed role credentials
        """
        if not isinstance(session, AliyunCloudSession):
            raise ValueError("Session must be an AliyunCloudSession instance")
            
        # 确保依赖项已安装
        try:
            from aliyunsdksts.request.v20150401 import AssumeRoleRequest
            import json
        except ImportError as e:
            raise ImportError(f"阿里云角色切换需要安装STS SDK: pip install aliyun-python-sdk-sts")

        try:
            # 获取角色切换参数
            role_session_name = kwargs.get('role_session_name', 'AliyunCloudAuditSession')
            policy = kwargs.get('policy')
            duration_seconds = kwargs.get('duration_seconds', 3600)
            
            # 创建AssumeRole请求
            client = session.get_client('sts')
            request = AssumeRoleRequest.AssumeRoleRequest()
            request.set_RoleArn(role_arn)
            request.set_RoleSessionName(role_session_name)
            request.set_DurationSeconds(duration_seconds)
            
            if policy:
                request.set_Policy(policy)
            
            # 执行角色切换
            response = client.do_action_with_exception(request)
            result = json.loads(response)
            
            # 提取临时凭证
            credentials = result.get('Credentials', {})
            access_key_id = credentials.get('AccessKeyId')
            access_key_secret = credentials.get('AccessKeySecret')
            security_token = credentials.get('SecurityToken')
            
            if not access_key_id or not access_key_secret:
                raise Exception("Failed to get temporary credentials from AssumeRole response")
            
            # 从原始会话获取区域ID，但优先使用传入的区域ID
            region_id = kwargs.get('region_id', session.aliyun_session.region_id)
            
            # 记录区域信息
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"在角色切换时使用区域: {region_id}")
            
            # 创建新的会话使用临时凭证
            new_aliyun_session = AliyunSession(
                access_key_id=access_key_id,
                access_key_secret=access_key_secret,
                region_id=region_id,
                security_token=security_token
            )
            
            return AliyunCloudSession(new_aliyun_session)
        except Exception as e:
            raise Exception(f"角色切换失败: {str(e)}")


class AliyunAuditorFactory(CloudAuditorFactory):
    """Factory for creating Aliyun auditors"""

    def create_session(self, **kwargs) -> CloudSession:
        authenticator = AliyunAuthenticator()
        session = authenticator.authenticate(**kwargs)

        # 阿里云的角色切换（如果提供了role_arn）
        if role_arn := kwargs.get('role_arn'):
            try:
                # 创建一个新的kwargs字典用于角色切换，确保包含region_id
                role_kwargs = {k: v for k, v in kwargs.items() if k != 'role_arn'}
                
                # 记录日志
                import logging
                logger = logging.getLogger(__name__)
                logger.info(f"角色切换时传递参数: {role_kwargs}")
                
                session = authenticator.switch_role(session, role_arn, **role_kwargs)
            except Exception as e:
                # 如果角色切换失败，给出明确的错误信息但不中断程序
                if "阿里云角色切换需要安装STS SDK" in str(e):
                    raise Exception(
                        f"角色切换失败: {str(e)}\n"
                        f"如果您不需要角色切换，请移除 --role-arn 参数直接使用基础凭证"
                    )
                else:
                    raise e

        return session

    def create_auditor(self, session: CloudSession, output_dir: str = "output") -> CloudAuditor:
        # 确保会话是 AliyunCloudSession 实例
        if not isinstance(session, AliyunCloudSession):
            raise ValueError("Session must be an AliyunCloudSession instance")

        from .auditor import AliyunAuditor
        return AliyunAuditor(session.aliyun_session, output_dir)


# 导入auditor类以便导出
from .auditor import AliyunAuditor

__all__ = [
    'AliyunProvider',
    'AliyunCloudSession', 
    'AliyunAuthenticator',
    'AliyunAuditor',
    'AliyunAuditorFactory',
]