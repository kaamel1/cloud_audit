"""阿里云RAM资源处理模块，负责获取RAM用户、角色、权限策略等资源信息。"""
import logging
import json
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class IAMAssetCollector:
    """阿里云RAM资源收集器"""

    def __init__(self, session):
        """
        初始化RAM资源收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        # 初始化RAM客户端
        self.ram_client = session.get_client('ram')

    def get_users(self) -> List[Dict[str, Any]]:
        """
        获取RAM用户信息

        Returns:
            List[Dict[str, Any]]: RAM用户列表
        """
        logger.info("获取RAM用户信息")
        users = []

        try:
            # 导入阿里云RAM SDK请求模块
            from aliyunsdkram.request.v20150501 import ListUsersRequest
            
            # 创建请求对象
            request = ListUsersRequest.ListUsersRequest()
            request.set_accept_format('json')
            
            # 执行请求
            response = self.ram_client.do_action_with_exception(request)
            response_dict = json.loads(response)
            
            # 处理用户数据
            for user in response_dict.get('Users', {}).get('User', []):
                user_info = {
                    'UserId': user.get('UserId'),
                    'UserName': user.get('UserName'),
                    'DisplayName': user.get('DisplayName'),
                    'MobilePhone': user.get('MobilePhone'),
                    'Email': user.get('Email'),
                    'Comments': user.get('Comments'),
                    'CreateDate': user.get('CreateDate'),
                    'UpdateDate': user.get('UpdateDate'),
                    'LastLoginDate': user.get('LastLoginDate'),
                }
                
                # 获取用户的权限策略
                user_policies = self.get_user_policies(user.get('UserName'))
                user_info['Policies'] = user_policies
                
                users.append(user_info)
                
            # 处理分页
            marker = response_dict.get('Marker')
            while marker:
                request = ListUsersRequest.ListUsersRequest()
                request.set_accept_format('json')
                request.set_Marker(marker)
                
                response = self.ram_client.do_action_with_exception(request)
                response_dict = json.loads(response)
                
                # 处理用户数据
                for user in response_dict.get('Users', {}).get('User', []):
                    user_info = {
                        'UserId': user.get('UserId'),
                        'UserName': user.get('UserName'),
                        'DisplayName': user.get('DisplayName'),
                        'MobilePhone': user.get('MobilePhone'),
                        'Email': user.get('Email'),
                        'Comments': user.get('Comments'),
                        'CreateDate': user.get('CreateDate'),
                        'UpdateDate': user.get('UpdateDate'),
                        'LastLoginDate': user.get('LastLoginDate'),
                    }
                    
                    # 获取用户的权限策略
                    user_policies = self.get_user_policies(user.get('UserName'))
                    user_info['Policies'] = user_policies
                    
                    users.append(user_info)
                
                marker = response_dict.get('Marker')
                
        except Exception as e:
            logger.error(f"获取RAM用户信息失败: {str(e)}")
            
        return users

    def get_user_policies(self, user_name: str) -> List[Dict[str, Any]]:
        """
        获取指定用户的权限策略

        Args:
            user_name: 用户名

        Returns:
            List[Dict[str, Any]]: 权限策略列表
        """
        policies = []
        
        try:
            # 导入阿里云RAM SDK请求模块
            from aliyunsdkram.request.v20150501 import ListPoliciesForUserRequest
            
            # 创建请求对象
            request = ListPoliciesForUserRequest.ListPoliciesForUserRequest()
            request.set_accept_format('json')
            request.set_UserName(user_name)
            
            # 执行请求
            response = self.ram_client.do_action_with_exception(request)
            response_dict = json.loads(response)
            
            # 处理策略数据
            for policy in response_dict.get('Policies', {}).get('Policy', []):
                policy_info = {
                    'PolicyName': policy.get('PolicyName'),
                    'PolicyType': policy.get('PolicyType'),
                    'Description': policy.get('Description'),
                    'DefaultVersion': policy.get('DefaultVersion'),
                    'AttachDate': policy.get('AttachDate'),
                }
                policies.append(policy_info)
                
            # 处理分页
            marker = response_dict.get('Marker')
            while marker:
                request = ListPoliciesForUserRequest.ListPoliciesForUserRequest()
                request.set_accept_format('json')
                request.set_UserName(user_name)
                request.set_Marker(marker)
                
                response = self.ram_client.do_action_with_exception(request)
                response_dict = json.loads(response)
                
                # 处理策略数据
                for policy in response_dict.get('Policies', {}).get('Policy', []):
                    policy_info = {
                        'PolicyName': policy.get('PolicyName'),
                        'PolicyType': policy.get('PolicyType'),
                        'Description': policy.get('Description'),
                        'DefaultVersion': policy.get('DefaultVersion'),
                        'AttachDate': policy.get('AttachDate'),
                    }
                    policies.append(policy_info)
                
                marker = response_dict.get('Marker')
                
        except Exception as e:
            logger.error(f"获取用户 {user_name} 的权限策略失败: {str(e)}")
            
        return policies

    def get_roles(self) -> List[Dict[str, Any]]:
        """
        获取RAM角色信息

        Returns:
            List[Dict[str, Any]]: RAM角色列表
        """
        logger.info("获取RAM角色信息")
        roles = []

        try:
            # 导入阿里云RAM SDK请求模块
            from aliyunsdkram.request.v20150501 import ListRolesRequest
            
            # 创建请求对象
            request = ListRolesRequest.ListRolesRequest()
            request.set_accept_format('json')
            
            # 执行请求
            response = self.ram_client.do_action_with_exception(request)
            response_dict = json.loads(response)
            
            # 处理角色数据
            for role in response_dict.get('Roles', {}).get('Role', []):
                role_info = {
                    'RoleId': role.get('RoleId'),
                    'RoleName': role.get('RoleName'),
                    'Arn': role.get('Arn'),
                    'Description': role.get('Description'),
                    'CreateDate': role.get('CreateDate'),
                    'UpdateDate': role.get('UpdateDate'),
                    'MaxSessionDuration': role.get('MaxSessionDuration'),
                }
                
                # 获取角色的权限策略
                role_policies = self.get_role_policies(role.get('RoleName'))
                role_info['Policies'] = role_policies
                
                roles.append(role_info)
                
            # 处理分页
            marker = response_dict.get('Marker')
            while marker:
                request = ListRolesRequest.ListRolesRequest()
                request.set_accept_format('json')
                request.set_Marker(marker)
                
                response = self.ram_client.do_action_with_exception(request)
                response_dict = json.loads(response)
                
                # 处理角色数据
                for role in response_dict.get('Roles', {}).get('Role', []):
                    role_info = {
                        'RoleId': role.get('RoleId'),
                        'RoleName': role.get('RoleName'),
                        'Arn': role.get('Arn'),
                        'Description': role.get('Description'),
                        'CreateDate': role.get('CreateDate'),
                        'UpdateDate': role.get('UpdateDate'),
                        'MaxSessionDuration': role.get('MaxSessionDuration'),
                    }
                    
                    # 获取角色的权限策略
                    role_policies = self.get_role_policies(role.get('RoleName'))
                    role_info['Policies'] = role_policies
                    
                    roles.append(role_info)
                
                marker = response_dict.get('Marker')
                
        except Exception as e:
            logger.error(f"获取RAM角色信息失败: {str(e)}")
            
        return roles

    def get_role_policies(self, role_name: str) -> List[Dict[str, Any]]:
        """
        获取指定角色的权限策略

        Args:
            role_name: 角色名

        Returns:
            List[Dict[str, Any]]: 权限策略列表
        """
        policies = []
        
        try:
            # 导入阿里云RAM SDK请求模块
            from aliyunsdkram.request.v20150501 import ListPoliciesForRoleRequest
            
            # 创建请求对象
            request = ListPoliciesForRoleRequest.ListPoliciesForRoleRequest()
            request.set_accept_format('json')
            request.set_RoleName(role_name)
            
            # 执行请求
            response = self.ram_client.do_action_with_exception(request)
            response_dict = json.loads(response)
            
            # 处理策略数据
            for policy in response_dict.get('Policies', {}).get('Policy', []):
                policy_info = {
                    'PolicyName': policy.get('PolicyName'),
                    'PolicyType': policy.get('PolicyType'),
                    'Description': policy.get('Description'),
                    'DefaultVersion': policy.get('DefaultVersion'),
                    'AttachDate': policy.get('AttachDate'),
                }
                policies.append(policy_info)
                
            # 处理分页
            marker = response_dict.get('Marker')
            while marker:
                request = ListPoliciesForRoleRequest.ListPoliciesForRoleRequest()
                request.set_accept_format('json')
                request.set_RoleName(role_name)
                request.set_Marker(marker)
                
                response = self.ram_client.do_action_with_exception(request)
                response_dict = json.loads(response)
                
                # 处理策略数据
                for policy in response_dict.get('Policies', {}).get('Policy', []):
                    policy_info = {
                        'PolicyName': policy.get('PolicyName'),
                        'PolicyType': policy.get('PolicyType'),
                        'Description': policy.get('Description'),
                        'DefaultVersion': policy.get('DefaultVersion'),
                        'AttachDate': policy.get('AttachDate'),
                    }
                    policies.append(policy_info)
                
                marker = response_dict.get('Marker')
                
        except Exception as e:
            logger.error(f"获取角色 {role_name} 的权限策略失败: {str(e)}")
            
        return policies

    def get_policies(self) -> List[Dict[str, Any]]:
        """
        获取RAM权限策略信息（仅用户自定义策略）

        Returns:
            List[Dict[str, Any]]: RAM权限策略列表
        """
        logger.info("获取RAM权限策略信息（仅用户自定义策略）")
        policies = []

        try:
            # 导入阿里云RAM SDK请求模块
            from aliyunsdkram.request.v20150501 import ListPoliciesRequest, GetPolicyVersionRequest
            
            # 创建请求对象
            request = ListPoliciesRequest.ListPoliciesRequest()
            request.set_accept_format('json')
            request.set_PolicyType('Custom')  # 只获取用户自定义策略
            
            # 执行请求
            response = self.ram_client.do_action_with_exception(request)
            response_dict = json.loads(response)
            
            # 处理策略数据
            for policy in response_dict.get('Policies', {}).get('Policy', []):
                policy_info = {
                    'PolicyName': policy.get('PolicyName'),
                    'PolicyType': policy.get('PolicyType'),
                    'Description': policy.get('Description'),
                    'DefaultVersion': policy.get('DefaultVersion'),
                    'CreateDate': policy.get('CreateDate'),
                    'UpdateDate': policy.get('UpdateDate'),
                    'AttachmentCount': policy.get('AttachmentCount'),
                }
                
                # 获取默认版本的策略文档
                try:
                    policy_version_request = GetPolicyVersionRequest.GetPolicyVersionRequest()
                    policy_version_request.set_accept_format('json')
                    policy_version_request.set_PolicyName(policy.get('PolicyName'))
                    policy_version_request.set_PolicyType('Custom')
                    policy_version_request.set_VersionId(policy.get('DefaultVersion'))
                    
                    policy_version_response = self.ram_client.do_action_with_exception(policy_version_request)
                    policy_version_dict = json.loads(policy_version_response)
                    
                    policy_info['PolicyDocument'] = policy_version_dict.get('PolicyVersion', {}).get('PolicyDocument')
                except Exception as e:
                    logger.warning(f"获取策略 {policy.get('PolicyName')} 的文档失败: {str(e)}")
                    policy_info['PolicyDocument'] = None
                
                policies.append(policy_info)
                
            # 处理分页
            marker = response_dict.get('Marker')
            while marker:
                request = ListPoliciesRequest.ListPoliciesRequest()
                request.set_accept_format('json')
                request.set_PolicyType('Custom')  # 只获取用户自定义策略
                request.set_Marker(marker)
                
                response = self.ram_client.do_action_with_exception(request)
                response_dict = json.loads(response)
                
                # 处理策略数据
                for policy in response_dict.get('Policies', {}).get('Policy', []):
                    policy_info = {
                        'PolicyName': policy.get('PolicyName'),
                        'PolicyType': policy.get('PolicyType'),
                        'Description': policy.get('Description'),
                        'DefaultVersion': policy.get('DefaultVersion'),
                        'CreateDate': policy.get('CreateDate'),
                        'UpdateDate': policy.get('UpdateDate'),
                        'AttachmentCount': policy.get('AttachmentCount'),
                    }
                    
                    # 获取默认版本的策略文档
                    try:
                        policy_version_request = GetPolicyVersionRequest.GetPolicyVersionRequest()
                        policy_version_request.set_accept_format('json')
                        policy_version_request.set_PolicyName(policy.get('PolicyName'))
                        policy_version_request.set_PolicyType('Custom')
                        policy_version_request.set_VersionId(policy.get('DefaultVersion'))
                        
                        policy_version_response = self.ram_client.do_action_with_exception(policy_version_request)
                        policy_version_dict = json.loads(policy_version_response)
                        
                        policy_info['PolicyDocument'] = policy_version_dict.get('PolicyVersion', {}).get('PolicyDocument')
                    except Exception as e:
                        logger.warning(f"获取策略 {policy.get('PolicyName')} 的文档失败: {str(e)}")
                        policy_info['PolicyDocument'] = None
                    
                    policies.append(policy_info)
                
                marker = response_dict.get('Marker')
                
        except Exception as e:
            logger.error(f"获取RAM权限策略信息失败: {str(e)}")
            
        return policies

    def get_all_iam_assets(self) -> Dict[str, Any]:
        """
        获取所有RAM区域相关资源
        注意：RAM资源完全是全局的，区域级别收集器返回空结果
        请使用 IAMGlobalAssetCollector 获取RAM资源

        Returns:
            Dict[str, Any]: 空的结果，因为RAM资源都是全局的
        """
        logger.info("RAM资源完全是全局的，区域级别收集器跳过")
        
        # RAM资源都是全局的，区域级别收集器返回空结果
        return {
            'users': {},
            'roles': {},
            'policies': {},
        } 