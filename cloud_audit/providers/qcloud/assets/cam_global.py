"""
腾讯云访问管理(CAM)全局资产收集器

负责收集腾讯云的访问管理全局资源，包括：
- CAM用户管理 - 全局服务
- CAM组管理 - 全局服务  
- CAM角色管理 - 全局服务
- CAM策略管理 - 全局服务
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class CAMGlobalAssetCollector:
    """CAM全局资产收集器"""
    
    def __init__(self, session):
        self.session = session
        # 初始化CAM客户端
        self.cam_client = session.get_client('cam')
        
    def get_cam_users(self) -> List[Dict[str, Any]]:
        """获取CAM用户列表（全局服务）"""
        logger.info("收集CAM用户（全局）")
        users = []
        
        try:
            # 导入腾讯云CAM SDK请求模块
            from tencentcloud.cam.v20190116 import models
            
            # 创建请求对象
            request = models.ListUsersRequest()
            
            # 执行请求
            response = self.cam_client.ListUsers(request)
            
            # 处理用户数据
            if hasattr(response, 'Data') and response.Data:
                for user in response.Data:
                    user_info = {
                        'Uin': getattr(user, 'Uin', None),
                        'Name': getattr(user, 'Name', None),
                        'UserName': getattr(user, 'Name', None),  # 兼容字段
                        'Uid': getattr(user, 'Uid', None),
                        'Remark': getattr(user, 'Remark', None),
                        'ConsoleLogin': getattr(user, 'ConsoleLogin', None),
                        'PhoneNum': getattr(user, 'PhoneNum', None),
                        'CountryCode': getattr(user, 'CountryCode', None),
                        'Email': getattr(user, 'Email', None),
                        'CreateTime': getattr(user, 'CreateTime', None),
                        'NickName': getattr(user, 'NickName', None),
                    }
                    users.append(user_info)
                    
        except Exception as e:
            logger.error(f"获取CAM用户信息失败: {str(e)}")
            
        return users
    
    def get_cam_groups(self) -> List[Dict[str, Any]]:
        """获取CAM用户组列表（全局服务）"""
        logger.info("收集CAM用户组（全局）")
        groups = []
        
        try:
            # 导入腾讯云CAM SDK请求模块
            from tencentcloud.cam.v20190116 import models
            
            # 创建请求对象
            request = models.ListGroupsRequest()
            
            # 执行请求
            response = self.cam_client.ListGroups(request)
            
            # 处理用户组数据
            if hasattr(response, 'GroupInfo') and response.GroupInfo:
                for group in response.GroupInfo:
                    group_info = {
                        'GroupId': getattr(group, 'GroupId', None),
                        'GroupName': getattr(group, 'GroupName', None),
                        'CreateTime': getattr(group, 'CreateTime', None),
                        'Remark': getattr(group, 'Remark', None),
                    }
                    groups.append(group_info)
                    
        except Exception as e:
            logger.error(f"获取CAM用户组信息失败: {str(e)}")
            
        return groups
    
    def get_cam_roles(self) -> List[Dict[str, Any]]:
        """获取CAM角色列表（全局服务）"""
        logger.info("收集CAM角色（全局）")
        roles = []
        
        try:
            # 导入腾讯云CAM SDK请求模块
            from tencentcloud.cam.v20190116 import models
            
            # 分页获取角色列表
            page = 1
            rp = 200  # 每页最大200条
            
            while True:
                # 创建请求对象
                request = models.DescribeRoleListRequest()
                request.Page = page
                request.Rp = rp
                
                # 执行请求
                response = self.cam_client.DescribeRoleList(request)
                
                # 处理角色数据
                current_page_roles = []
                if hasattr(response, 'List') and response.List:
                    for role in response.List:
                        role_info = {
                            'RoleId': getattr(role, 'RoleId', None),
                            'RoleName': getattr(role, 'RoleName', None),
                            'PolicyDocument': getattr(role, 'PolicyDocument', None),
                            'Description': getattr(role, 'Description', None),
                            'AddTime': getattr(role, 'AddTime', None),
                            'UpdateTime': getattr(role, 'UpdateTime', None),
                            'MaxSessionDuration': getattr(role, 'MaxSessionDuration', None),
                            'SessionDuration': getattr(role, 'SessionDuration', None),
                        }
                        current_page_roles.append(role_info)
                
                roles.extend(current_page_roles)
                
                # 检查是否还有更多数据
                if len(current_page_roles) < rp:
                    break
                
                page += 1
                    
        except Exception as e:
            logger.error(f"获取CAM角色信息失败: {str(e)}")
            
        return roles
    
    def get_cam_policies(self) -> List[Dict[str, Any]]:
        """获取CAM策略列表（全局服务，仅返回用户自定义策略）"""
        logger.info("收集CAM策略（全局）")
        policies = []
        
        try:
            # 导入腾讯云CAM SDK请求模块
            from tencentcloud.cam.v20190116 import models
            
            # 分页获取策略列表
            page = 1
            rp = 200  # 每页最大200条
            
            while True:
                # 创建请求对象
                request = models.ListPoliciesRequest()
                request.Page = page
                request.Rp = rp
                # 使用Scope参数直接过滤：'Local'只获取自定义策略，'QCS'只获取预设策略，'All'获取所有策略
                request.Scope = 'Local'  # 只获取用户自定义策略
                
                # 执行请求
                response = self.cam_client.ListPolicies(request)
                
                # 处理策略数据
                current_page_policies = []
                if hasattr(response, 'List') and response.List:
                    for policy in response.List:
                        # 已通过Scope参数过滤，直接处理所有返回的策略
                        policy_info = {
                            'PolicyId': getattr(policy, 'PolicyId', None),
                            'PolicyName': getattr(policy, 'PolicyName', None),
                            'AddTime': getattr(policy, 'AddTime', None),
                            'Type': getattr(policy, 'Type', None),
                            'Description': getattr(policy, 'Description', None),
                            'CreateMode': getattr(policy, 'CreateMode', None),
                            'Attachments': getattr(policy, 'Attachments', None),
                            'ServiceType': getattr(policy, 'ServiceType', None),
                            'IsAttached': getattr(policy, 'IsAttached', None),
                            'Deactived': getattr(policy, 'Deactived', None),
                            'DeactivedDetail': getattr(policy, 'DeactivedDetail', None),
                            'IsServiceLinkedPolicy': getattr(policy, 'IsServiceLinkedPolicy', None),
                        }
                        current_page_policies.append(policy_info)
                
                policies.extend(current_page_policies)
                
                # 检查是否还有更多数据
                if len(current_page_policies) < rp:
                    break
                
                page += 1
                    
        except Exception as e:
            logger.error(f"获取CAM策略信息失败: {str(e)}")
            
        return policies
    
    def get_cam_api_keys(self) -> List[Dict[str, Any]]:
        """获取CAM API密钥列表（全局服务）"""
        logger.info("收集CAM API密钥（全局）")
        api_keys = []
        
        try:
            # 导入腾讯云CAM SDK请求模块
            from tencentcloud.cam.v20190116 import models
            
            # 创建请求对象
            request = models.ListAccessKeysRequest()
            
            # 执行请求
            response = self.cam_client.ListAccessKeys(request)
            
            # 处理API密钥数据
            if hasattr(response, 'AccessKeys') and response.AccessKeys:
                for key in response.AccessKeys:
                    key_info = {
                        'AccessKeyId': getattr(key, 'AccessKeyId', None),
                        'SecretId': getattr(key, 'AccessKeyId', None),  # 兼容字段
                        'Status': getattr(key, 'Status', None),
                        'CreateTime': getattr(key, 'CreateTime', None),
                        'Description': getattr(key, 'Description', None),
                    }
                    api_keys.append(key_info)
                    
        except Exception as e:
            logger.error(f"获取CAM API密钥信息失败: {str(e)}")
            
        return api_keys
    
    def get_cam_login_profiles(self) -> List[Dict[str, Any]]:
        """获取CAM登录配置列表（全局服务）"""
        logger.info("收集CAM登录配置（全局）")
        login_profiles = []
        
        try:
            # 先获取所有用户，然后获取每个用户的登录配置
            users = self.get_cam_users()
            
            # 导入腾讯云CAM SDK请求模块
            from tencentcloud.cam.v20190116 import models
            
            for user in users:
                user_name = user.get('UserName') or user.get('Name')
                if not user_name:
                    continue
                    
                try:
                    # 创建请求对象
                    request = models.GetLoginProfileRequest()
                    request.UserName = user_name
                    
                    # 执行请求
                    response = self.cam_client.GetLoginProfile(request)
                    
                    # 处理登录配置数据
                    if hasattr(response, 'LoginProfile') and response.LoginProfile:
                        login_profile = response.LoginProfile
                        profile_info = {
                            'UserName': user_name,
                            'UserId': user.get('Uid'),
                            'PasswordResetRequired': getattr(login_profile, 'PasswordResetRequired', None),
                            'MfaFlag': getattr(login_profile, 'MfaFlag', None),
                            'CreateTime': getattr(login_profile, 'CreateTime', None),
                            'ModifyTime': getattr(login_profile, 'ModifyTime', None),
                        }
                        login_profiles.append(profile_info)
                        
                except Exception as user_error:
                    # 如果某个用户没有登录配置或获取失败，跳过该用户
                    logger.debug(f"获取用户 {user_name} 的登录配置失败: {str(user_error)}")
                    continue
                    
        except Exception as e:
            logger.error(f"获取CAM登录配置信息失败: {str(e)}")
            
        return login_profiles
        
    def get_all_cam_global_assets(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        获取所有CAM全局资源，按类型分开并返回单个资源项

        Returns:
            Dict[str, Dict[str, Dict[str, Any]]]: 按类型分开的CAM全局资源，每个资源项单独存储
        """
        logger.info("开始收集所有CAM全局资源")
        
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
        
        logger.info("CAM全局资源收集完成")
        return {
            'cam_users': users,
            'cam_groups': groups,
            'cam_roles': roles,
            'cam_policies': policies,
            'cam_api_keys': api_keys,
            'cam_login_profiles': login_profiles
        } 