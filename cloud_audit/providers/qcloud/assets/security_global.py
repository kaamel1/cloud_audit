"""
腾讯云安全全局资产收集器

负责收集腾讯云的全局安全资源，包括：
- 访问管理 (CAM) - 全局服务
注意：SSL证书管理、KMS密钥管理实际上是区域服务，应在区域collector中处理
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class SecurityGlobalAssetCollector:
    """全局安全资产收集器"""
    
    def __init__(self, session):
        self.session = session
        
    def get_cam_users(self) -> List[Dict[str, Any]]:
        """获取CAM用户列表（全局服务）"""
        logger.info("收集CAM用户（全局）")
        return []
    
    def get_cam_groups(self) -> List[Dict[str, Any]]:
        """获取CAM用户组列表（全局服务）"""
        logger.info("收集CAM用户组（全局）")
        return []
    
    def get_cam_roles(self) -> List[Dict[str, Any]]:
        """获取CAM角色列表（全局服务）"""
        logger.info("收集CAM角色（全局）")
        return []
    
    def get_cam_policies(self) -> List[Dict[str, Any]]:
        """获取CAM策略列表（全局服务）"""
        logger.info("收集CAM策略（全局）")
        return []
    
    def get_cam_api_keys(self) -> List[Dict[str, Any]]:
        """获取CAM API密钥列表（全局服务）"""
        logger.info("收集CAM API密钥（全局）")
        return []
    
    def get_cam_login_profiles(self) -> List[Dict[str, Any]]:
        """获取CAM登录配置列表（全局服务）"""
        logger.info("收集CAM登录配置（全局）")
        return []
        
    def get_all_security_global_assets(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        获取所有安全全局资源，按类型分开并返回单个资源项

        Returns:
            Dict[str, Dict[str, Dict[str, Any]]]: 按类型分开的安全全局资源，每个资源项单独存储
        """
        logger.info("开始收集所有安全全局资源")
        
        users = {user.get('UserName', user.get('UserId', f'user_{i}')): user 
                for i, user in enumerate(self.get_cam_users())}
        groups = {group.get('GroupName', group.get('GroupId', f'group_{i}')): group 
                 for i, group in enumerate(self.get_cam_groups())}
        roles = {role.get('RoleName', role.get('RoleId', f'role_{i}')): role 
                for i, role in enumerate(self.get_cam_roles())}
        policies = {policy.get('PolicyName', policy.get('PolicyId', f'policy_{i}')): policy 
                   for i, policy in enumerate(self.get_cam_policies())}
        api_keys = {key.get('AccessKeyId', key.get('SecretId', f'key_{i}')): key 
                   for i, key in enumerate(self.get_cam_api_keys())}
        login_profiles = {profile.get('UserName', profile.get('UserId', f'profile_{i}')): profile 
                         for i, profile in enumerate(self.get_cam_login_profiles())}
        
        logger.info("安全全局资源收集完成")
        return {
            'cam_users': users,
            'cam_groups': groups,
            'cam_roles': roles,
            'cam_policies': policies,
            'cam_api_keys': api_keys,
            'cam_login_profiles': login_profiles
        } 