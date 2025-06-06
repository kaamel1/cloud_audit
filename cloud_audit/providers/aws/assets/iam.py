"""
AWS IAM资源处理模块，负责获取用户、角色、策略等IAM资源信息。
"""
import boto3
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class IAMAssetCollector:
    """AWS IAM资源收集器"""

    def __init__(self, session):
        """
        初始化IAM资源收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        self.iam_client = session.get_client('iam')

    def get_iam_users(self) -> List[Dict[str, Any]]:
        """
        获取IAM用户信息

        Returns:
            List[Dict[str, Any]]: IAM用户列表
        """
        logger.info("获取IAM用户信息")
        users = []

        try:
            # 获取所有IAM用户
            response = self.iam_client.list_users()

            for user in response.get('Users', []):
                # 获取用户的访问密钥
                access_keys = []
                try:
                    keys_response = self.iam_client.list_access_keys(UserName=user.get('UserName'))
                    access_keys = keys_response.get('AccessKeyMetadata', [])
                except Exception as e:
                    logger.error(f"获取用户 {user.get('UserName')} 的访问密钥失败: {str(e)}")

                # 获取用户的组
                groups = []
                try:
                    groups_response = self.iam_client.list_groups_for_user(UserName=user.get('UserName'))
                    groups = groups_response.get('Groups', [])
                except Exception as e:
                    logger.error(f"获取用户 {user.get('UserName')} 的组失败: {str(e)}")

                # 获取用户的附加策略
                attached_policies = []
                try:
                    policies_response = self.iam_client.list_attached_user_policies(UserName=user.get('UserName'))
                    attached_policies = policies_response.get('AttachedPolicies', [])
                except Exception as e:
                    logger.error(f"获取用户 {user.get('UserName')} 的附加策略失败: {str(e)}")

                # 获取用户的内联策略
                inline_policies = []
                try:
                    inline_policy_names = self.iam_client.list_user_policies(UserName=user.get('UserName'))
                    for policy_name in inline_policy_names.get('PolicyNames', []):
                        try:
                            policy_response = self.iam_client.get_user_policy(
                                UserName=user.get('UserName'),
                                PolicyName=policy_name
                            )
                            inline_policies.append({
                                'PolicyName': policy_name,
                                'PolicyDocument': policy_response.get('PolicyDocument')
                            })
                        except Exception as e:
                            logger.error(f"获取用户 {user.get('UserName')} 的内联策略 {policy_name} 失败: {str(e)}")
                except Exception as e:
                    logger.error(f"获取用户 {user.get('UserName')} 的内联策略列表失败: {str(e)}")

                user_info = {
                    'UserName': user.get('UserName'),
                    'UserId': user.get('UserId'),
                    'Arn': user.get('Arn'),
                    'CreateDate': user.get('CreateDate'),
                    'PasswordLastUsed': user.get('PasswordLastUsed'),
                    'Path': user.get('Path'),
                    'AccessKeys': access_keys,
                    'Groups': groups,
                    'AttachedPolicies': attached_policies,
                    'InlinePolicies': inline_policies
                }
                users.append(user_info)

            # 处理分页
            while 'Marker' in response:
                response = self.iam_client.list_users(
                    Marker=response['Marker']
                )

                for user in response.get('Users', []):
                    # 获取用户的访问密钥
                    access_keys = []
                    try:
                        keys_response = self.iam_client.list_access_keys(UserName=user.get('UserName'))
                        access_keys = keys_response.get('AccessKeyMetadata', [])
                    except Exception as e:
                        logger.error(f"获取用户 {user.get('UserName')} 的访问密钥失败: {str(e)}")

                    # 获取用户的组
                    groups = []
                    try:
                        groups_response = self.iam_client.list_groups_for_user(UserName=user.get('UserName'))
                        groups = groups_response.get('Groups', [])
                    except Exception as e:
                        logger.error(f"获取用户 {user.get('UserName')} 的组失败: {str(e)}")

                    # 获取用户的附加策略
                    attached_policies = []
                    try:
                        policies_response = self.iam_client.list_attached_user_policies(UserName=user.get('UserName'))
                        attached_policies = policies_response.get('AttachedPolicies', [])
                    except Exception as e:
                        logger.error(f"获取用户 {user.get('UserName')} 的附加策略失败: {str(e)}")

                    # 获取用户的内联策略
                    inline_policies = []
                    try:
                        inline_policy_names = self.iam_client.list_user_policies(UserName=user.get('UserName'))
                        for policy_name in inline_policy_names.get('PolicyNames', []):
                            try:
                                policy_response = self.iam_client.get_user_policy(
                                    UserName=user.get('UserName'),
                                    PolicyName=policy_name
                                )
                                inline_policies.append({
                                    'PolicyName': policy_name,
                                    'PolicyDocument': policy_response.get('PolicyDocument')
                                })
                            except Exception as e:
                                logger.error(f"获取用户 {user.get('UserName')} 的内联策略 {policy_name} 失败: {str(e)}")
                    except Exception as e:
                        logger.error(f"获取用户 {user.get('UserName')} 的内联策略列表失败: {str(e)}")

                    user_info = {
                        'UserName': user.get('UserName'),
                        'UserId': user.get('UserId'),
                        'Arn': user.get('Arn'),
                        'CreateDate': user.get('CreateDate'),
                        'PasswordLastUsed': user.get('PasswordLastUsed'),
                        'Path': user.get('Path'),
                        'AccessKeys': access_keys,
                        'Groups': groups,
                        'AttachedPolicies': attached_policies,
                        'InlinePolicies': inline_policies
                    }
                    users.append(user_info)

        except Exception as e:
            logger.error(f"获取IAM用户信息失败: {str(e)}")

        return users

    def get_iam_roles(self) -> List[Dict[str, Any]]:
        """
        获取IAM角色信息

        Returns:
            List[Dict[str, Any]]: IAM角色列表
        """
        logger.info("获取IAM角色信息")
        roles = []

        try:
            # 获取所有IAM角色
            response = self.iam_client.list_roles()

            for role in response.get('Roles', []):
                # 获取角色的附加策略
                attached_policies = []
                try:
                    policies_response = self.iam_client.list_attached_role_policies(RoleName=role.get('RoleName'))
                    attached_policies = policies_response.get('AttachedPolicies', [])
                except Exception as e:
                    logger.error(f"获取角色 {role.get('RoleName')} 的附加策略失败: {str(e)}")

                # 获取角色的内联策略
                inline_policies = []
                try:
                    inline_policy_names = self.iam_client.list_role_policies(RoleName=role.get('RoleName'))
                    for policy_name in inline_policy_names.get('PolicyNames', []):
                        try:
                            policy_response = self.iam_client.get_role_policy(
                                RoleName=role.get('RoleName'),
                                PolicyName=policy_name
                            )
                            inline_policies.append({
                                'PolicyName': policy_name,
                                'PolicyDocument': policy_response.get('PolicyDocument')
                            })
                        except Exception as e:
                            logger.error(f"获取角色 {role.get('RoleName')} 的内联策略 {policy_name} 失败: {str(e)}")
                except Exception as e:
                    logger.error(f"获取角色 {role.get('RoleName')} 的内联策略列表失败: {str(e)}")

                role_info = {
                    'RoleName': role.get('RoleName'),
                    'RoleId': role.get('RoleId'),
                    'Arn': role.get('Arn'),
                    'CreateDate': role.get('CreateDate'),
                    'Path': role.get('Path'),
                    'AssumeRolePolicyDocument': role.get('AssumeRolePolicyDocument'),
                    'Description': role.get('Description'),
                    'MaxSessionDuration': role.get('MaxSessionDuration'),
                    'PermissionsBoundary': role.get('PermissionsBoundary'),
                    'Tags': role.get('Tags', []),
                    'AttachedPolicies': attached_policies,
                    'InlinePolicies': inline_policies
                }
                roles.append(role_info)

            # 处理分页
            while 'Marker' in response:
                response = self.iam_client.list_roles(
                    Marker=response['Marker']
                )

                for role in response.get('Roles', []):
                    # 获取角色的附加策略
                    attached_policies = []
                    try:
                        policies_response = self.iam_client.list_attached_role_policies(RoleName=role.get('RoleName'))
                        attached_policies = policies_response.get('AttachedPolicies', [])
                    except Exception as e:
                        logger.error(f"获取角色 {role.get('RoleName')} 的附加策略失败: {str(e)}")

                    # 获取角色的内联策略
                    inline_policies = []
                    try:
                        inline_policy_names = self.iam_client.list_role_policies(RoleName=role.get('RoleName'))
                        for policy_name in inline_policy_names.get('PolicyNames', []):
                            try:
                                policy_response = self.iam_client.get_role_policy(
                                    RoleName=role.get('RoleName'),
                                    PolicyName=policy_name
                                )
                                inline_policies.append({
                                    'PolicyName': policy_name,
                                    'PolicyDocument': policy_response.get('PolicyDocument')
                                })
                            except Exception as e:
                                logger.error(f"获取角色 {role.get('RoleName')} 的内联策略 {policy_name} 失败: {str(e)}")
                    except Exception as e:
                        logger.error(f"获取角色 {role.get('RoleName')} 的内联策略列表失败: {str(e)}")

                    role_info = {
                        'RoleName': role.get('RoleName'),
                        'RoleId': role.get('RoleId'),
                        'Arn': role.get('Arn'),
                        'CreateDate': role.get('CreateDate'),
                        'Path': role.get('Path'),
                        'AssumeRolePolicyDocument': role.get('AssumeRolePolicyDocument'),
                        'Description': role.get('Description'),
                        'MaxSessionDuration': role.get('MaxSessionDuration'),
                        'PermissionsBoundary': role.get('PermissionsBoundary'),
                        'Tags': role.get('Tags', []),
                        'AttachedPolicies': attached_policies,
                        'InlinePolicies': inline_policies
                    }
                    roles.append(role_info)

        except Exception as e:
            logger.error(f"获取IAM角色信息失败: {str(e)}")

        return roles

    def get_iam_policies(self) -> List[Dict[str, Any]]:
        """
        获取IAM策略信息

        Returns:
            List[Dict[str, Any]]: IAM策略列表
        """
        logger.info("获取IAM策略信息")
        policies = []

        try:
            # 获取所有IAM策略
            response = self.iam_client.list_policies(
                # Scope='All'  # 获取所有策略，包括AWS托管策略和客户托管策略
                Scope='Local'  # 只获取客户管理的策略
            )

            for policy in response.get('Policies', []):
                # 获取策略的版本详情
                policy_detail = {}
                try:
                    if policy.get('DefaultVersionId'):
                        version_response = self.iam_client.get_policy_version(
                            PolicyArn=policy.get('Arn'),
                            VersionId=policy.get('DefaultVersionId')
                        )
                        policy_detail = version_response.get('PolicyVersion', {})
                except Exception as e:
                    logger.error(f"获取策略 {policy.get('PolicyName')} 的版本详情失败: {str(e)}")

                policy_info = {
                    'PolicyName': policy.get('PolicyName'),
                    'PolicyId': policy.get('PolicyId'),
                    'Arn': policy.get('Arn'),
                    'Path': policy.get('Path'),
                    'DefaultVersionId': policy.get('DefaultVersionId'),
                    'AttachmentCount': policy.get('AttachmentCount'),
                    'PermissionsBoundaryUsageCount': policy.get('PermissionsBoundaryUsageCount'),
                    'IsAttachable': policy.get('IsAttachable'),
                    'CreateDate': policy.get('CreateDate'),
                    'UpdateDate': policy.get('UpdateDate'),
                    'PolicyDetail': policy_detail.get('Document') if policy_detail else {}
                }
                policies.append(policy_info)

            # 处理分页
            while 'Marker' in response:
                response = self.iam_client.list_policies(
                    # Scope='All',
                    Scope='Local',
                    Marker=response['Marker']
                )

                for policy in response.get('Policies', []):
                    # 获取策略的版本详情
                    policy_detail = {}
                    try:
                        if policy.get('DefaultVersionId'):
                            version_response = self.iam_client.get_policy_version(
                                PolicyArn=policy.get('Arn'),
                                VersionId=policy.get('DefaultVersionId')
                            )
                            policy_detail = version_response.get('PolicyVersion', {})
                    except Exception as e:
                        logger.error(f"获取策略 {policy.get('PolicyName')} 的版本详情失败: {str(e)}")

                    policy_info = {
                        'PolicyName': policy.get('PolicyName'),
                        'PolicyId': policy.get('PolicyId'),
                        'Arn': policy.get('Arn'),
                        'Path': policy.get('Path'),
                        'DefaultVersionId': policy.get('DefaultVersionId'),
                        'AttachmentCount': policy.get('AttachmentCount'),
                        'PermissionsBoundaryUsageCount': policy.get('PermissionsBoundaryUsageCount'),
                        'IsAttachable': policy.get('IsAttachable'),
                        'CreateDate': policy.get('CreateDate'),
                        'UpdateDate': policy.get('UpdateDate'),
                        'PolicyDetail': policy_detail.get('Document') if policy_detail else {}
                    }
                    policies.append(policy_info)

        except Exception as e:
            logger.error(f"获取IAM策略信息失败: {str(e)}")

        return policies

    def get_iam_groups(self) -> List[Dict[str, Any]]:
        """
        获取IAM组信息

        Returns:
            List[Dict[str, Any]]: IAM组列表
        """
        logger.info("获取IAM组信息")
        groups = []

        try:
            # 获取所有IAM组
            response = self.iam_client.list_groups()

            for group in response.get('Groups', []):
                # 获取组的附加策略
                attached_policies = []
                try:
                    policies_response = self.iam_client.list_attached_group_policies(GroupName=group.get('GroupName'))
                    attached_policies = policies_response.get('AttachedPolicies', [])
                except Exception as e:
                    logger.error(f"获取组 {group.get('GroupName')} 的附加策略失败: {str(e)}")

                # 获取组的内联策略
                inline_policies = []
                try:
                    inline_policy_names = self.iam_client.list_group_policies(GroupName=group.get('GroupName'))
                    for policy_name in inline_policy_names.get('PolicyNames', []):
                        try:
                            policy_response = self.iam_client.get_group_policy(
                                GroupName=group.get('GroupName'),
                                PolicyName=policy_name
                            )
                            inline_policies.append({
                                'PolicyName': policy_name,
                                'PolicyDocument': policy_response.get('PolicyDocument')
                            })
                        except Exception as e:
                            logger.error(f"获取组 {group.get('GroupName')} 的内联策略 {policy_name} 失败: {str(e)}")
                except Exception as e:
                    logger.error(f"获取组 {group.get('GroupName')} 的内联策略列表失败: {str(e)}")

                # 获取组的用户
                group_users = []
                try:
                    users_response = self.iam_client.get_group(GroupName=group.get('GroupName'))
                    group_users = users_response.get('Users', [])
                except Exception as e:
                    logger.error(f"获取组 {group.get('GroupName')} 的用户失败: {str(e)}")

                group_info = {
                    'GroupName': group.get('GroupName'),
                    'GroupId': group.get('GroupId'),
                    'Arn': group.get('Arn'),
                    'CreateDate': group.get('CreateDate'),
                    'Path': group.get('Path'),
                    'AttachedPolicies': attached_policies,
                    'InlinePolicies': inline_policies,
                    'Users': [{'UserName': user.get('UserName'), 'UserId': user.get('UserId'), 'Arn': user.get('Arn')} for user in group_users]
                }
                groups.append(group_info)

            # 处理分页
            while 'Marker' in response:
                response = self.iam_client.list_groups(
                    Marker=response['Marker']
                )

                for group in response.get('Groups', []):
                    # 获取组的附加策略
                    attached_policies = []
                    try:
                        policies_response = self.iam_client.list_attached_group_policies(GroupName=group.get('GroupName'))
                        attached_policies = policies_response.get('AttachedPolicies', [])
                    except Exception as e:
                        logger.error(f"获取组 {group.get('GroupName')} 的附加策略失败: {str(e)}")

                    # 获取组的内联策略
                    inline_policies = []
                    try:
                        inline_policy_names = self.iam_client.list_group_policies(GroupName=group.get('GroupName'))
                        for policy_name in inline_policy_names.get('PolicyNames', []):
                            try:
                                policy_response = self.iam_client.get_group_policy(
                                    GroupName=group.get('GroupName'),
                                    PolicyName=policy_name
                                )
                                inline_policies.append({
                                    'PolicyName': policy_name,
                                    'PolicyDocument': policy_response.get('PolicyDocument')
                                })
                            except Exception as e:
                                logger.error(f"获取组 {group.get('GroupName')} 的内联策略 {policy_name} 失败: {str(e)}")
                    except Exception as e:
                        logger.error(f"获取组 {group.get('GroupName')} 的内联策略列表失败: {str(e)}")

                    # 获取组的用户
                    group_users = []
                    try:
                        users_response = self.iam_client.get_group(GroupName=group.get('GroupName'))
                        group_users = users_response.get('Users', [])
                    except Exception as e:
                        logger.error(f"获取组 {group.get('GroupName')} 的用户失败: {str(e)}")

                    group_info = {
                        'GroupName': group.get('GroupName'),
                        'GroupId': group.get('GroupId'),
                        'Arn': group.get('Arn'),
                        'CreateDate': group.get('CreateDate'),
                        'Path': group.get('Path'),
                        'AttachedPolicies': attached_policies,
                        'InlinePolicies': inline_policies,
                        'Users': [{'UserName': user.get('UserName'), 'UserId': user.get('UserId'), 'Arn': user.get('Arn')} for user in group_users]
                    }
                    groups.append(group_info)

        except Exception as e:
            logger.error(f"获取IAM组信息失败: {str(e)}")

        return groups

    def get_all_iam_assets(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        获取所有IAM资源，按类型分开并返回单个资源项

        Returns:
            Dict[str, Dict[str, Dict[str, Any]]]: 按类型分开的IAM资源，每个资源项单独存储
        """
        users = {user['UserName']: user for user in self.get_iam_users()}
        roles = {role['RoleName']: role for role in self.get_iam_roles()}
        policies = {policy['PolicyName']: policy for policy in self.get_iam_policies()}
        groups = {group['GroupName']: group for group in self.get_iam_groups()}
        
        return {
            'users': users,
            'roles': roles,
            'policies': policies,
            'groups': groups
        } 