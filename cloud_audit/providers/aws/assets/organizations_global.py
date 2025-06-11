"""
AWS Organizations全局资源处理模块，负责获取组织、账户、组织单位、服务控制策略等企业级管理全局资源信息。
Organizations是AWS的全局服务，在不同区域获取到的数据是一致的。
"""
import boto3
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class OrganizationsGlobalAssetCollector:
    """AWS Organizations全局资源收集器"""

    def __init__(self, session):
        """
        初始化Organizations全局资源收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        self.organizations_client = session.get_client('organizations')

    def get_organization(self) -> Optional[Dict[str, Any]]:
        """
        获取组织信息

        Returns:
            Optional[Dict[str, Any]]: 组织信息，如果没有组织则返回None
        """
        logger.info("获取AWS Organizations组织信息")
        organization = None

        try:
            org_response = self.organizations_client.describe_organization()
            organization = org_response['Organization']
            
            # 获取组织的根信息
            roots = self.get_roots()
            if roots:
                organization['Roots'] = roots
            
            logger.info(f"组织ID: {organization.get('Id')}, 主账户: {organization.get('MasterAccountId')}")

        except self.organizations_client.exceptions.AWSOrganizationsNotInUseException:
            logger.info("当前账户未使用AWS Organizations")
        except Exception as e:
            logger.error(f"获取组织信息失败: {str(e)}")

        return organization

    def get_accounts(self) -> List[Dict[str, Any]]:
        """
        获取组织中的所有账户

        Returns:
            List[Dict[str, Any]]: 账户列表
        """
        logger.info("获取AWS Organizations账户信息")
        accounts = []

        try:
            next_token = None
            while True:
                if next_token:
                    response = self.organizations_client.list_accounts(NextToken=next_token)
                else:
                    response = self.organizations_client.list_accounts()
                
                for account in response.get('Accounts', []):
                    # 获取账户的标签
                    tags = []
                    try:
                        tags_response = self.organizations_client.list_tags_for_resource(
                            ResourceId=account['Id']
                        )
                        tags = tags_response.get('Tags', [])
                    except Exception as e:
                        logger.warning(f"获取账户 {account['Id']} 标签失败: {str(e)}")

                    # 获取账户父级组织单位
                    parents = []
                    try:
                        parents_response = self.organizations_client.list_parents(
                            ChildId=account['Id']
                        )
                        parents = parents_response.get('Parents', [])
                    except Exception as e:
                        logger.warning(f"获取账户 {account['Id']} 父级信息失败: {str(e)}")

                    account_info = {
                        'Id': account.get('Id'),
                        'Arn': account.get('Arn'),
                        'Email': account.get('Email'),
                        'Name': account.get('Name'),
                        'Status': account.get('Status'),
                        'JoinedMethod': account.get('JoinedMethod'),
                        'JoinedTimestamp': account.get('JoinedTimestamp'),
                        'Tags': tags,
                        'Parents': parents
                    }
                    accounts.append(account_info)
                
                if 'NextToken' in response:
                    next_token = response['NextToken']
                else:
                    break

        except Exception as e:
            logger.error(f"获取账户信息失败: {str(e)}")

        return accounts

    def get_roots(self) -> List[Dict[str, Any]]:
        """
        获取组织根信息

        Returns:
            List[Dict[str, Any]]: 根列表
        """
        logger.info("获取AWS Organizations根信息")
        roots = []

        try:
            next_token = None
            while True:
                if next_token:
                    response = self.organizations_client.list_roots(NextToken=next_token)
                else:
                    response = self.organizations_client.list_roots()
                
                for root in response.get('Roots', []):
                    # 获取根的策略类型
                    policy_types = []
                    try:
                        policy_types_response = self.organizations_client.list_policy_types_for_target(
                            TargetId=root['Id']
                        )
                        policy_types = policy_types_response.get('PolicyTypes', [])
                    except Exception as e:
                        logger.warning(f"获取根 {root['Id']} 策略类型失败: {str(e)}")

                    root_info = {
                        'Id': root.get('Id'),
                        'Arn': root.get('Arn'),
                        'Name': root.get('Name'),
                        'PolicyTypes': policy_types
                    }
                    roots.append(root_info)
                
                if 'NextToken' in response:
                    next_token = response['NextToken']
                else:
                    break

        except Exception as e:
            logger.error(f"获取根信息失败: {str(e)}")

        return roots

    def get_organizational_units(self) -> List[Dict[str, Any]]:
        """
        获取组织单位信息

        Returns:
            List[Dict[str, Any]]: 组织单位列表
        """
        logger.info("获取AWS Organizations组织单位信息")
        all_ous = []

        try:
            # 首先获取根
            roots = self.get_roots()
            
            for root in roots:
                root_id = root['Id']
                ous = self._get_ous_recursive(root_id)
                all_ous.extend(ous)

        except Exception as e:
            logger.error(f"获取组织单位信息失败: {str(e)}")

        return all_ous

    def _get_ous_recursive(self, parent_id: str) -> List[Dict[str, Any]]:
        """
        递归获取组织单位

        Args:
            parent_id: 父级ID

        Returns:
            List[Dict[str, Any]]: 组织单位列表
        """
        ous = []
        
        try:
            next_token = None
            while True:
                if next_token:
                    response = self.organizations_client.list_organizational_units_for_parent(
                        ParentId=parent_id,
                        NextToken=next_token
                    )
                else:
                    response = self.organizations_client.list_organizational_units_for_parent(ParentId=parent_id)
                
                for ou in response.get('OrganizationalUnits', []):
                    # 获取OU的标签
                    tags = []
                    try:
                        tags_response = self.organizations_client.list_tags_for_resource(
                            ResourceId=ou['Id']
                        )
                        tags = tags_response.get('Tags', [])
                    except Exception as e:
                        logger.warning(f"获取OU {ou['Id']} 标签失败: {str(e)}")

                    # 获取OU的策略类型
                    policy_types = []
                    try:
                        policy_types_response = self.organizations_client.list_policy_types_for_target(
                            TargetId=ou['Id']
                        )
                        policy_types = policy_types_response.get('PolicyTypes', [])
                    except Exception as e:
                        logger.warning(f"获取OU {ou['Id']} 策略类型失败: {str(e)}")

                    ou_info = {
                        'Id': ou.get('Id'),
                        'Arn': ou.get('Arn'),
                        'Name': ou.get('Name'),
                        'Tags': tags,
                        'PolicyTypes': policy_types
                    }
                    ous.append(ou_info)
                    
                    # 递归获取子OU
                    child_ous = self._get_ous_recursive(ou['Id'])
                    ous.extend(child_ous)
                
                if 'NextToken' in response:
                    next_token = response['NextToken']
                else:
                    break
                    
        except Exception as e:
            logger.error(f"获取父级 {parent_id} 的OU失败: {str(e)}")
            
        return ous

    def get_policies(self) -> List[Dict[str, Any]]:
        """
        获取组织策略信息

        Returns:
            List[Dict[str, Any]]: 策略列表
        """
        logger.info("获取AWS Organizations策略信息")
        all_policies = []

        try:
            # 获取不同类型的策略
            policy_types = ['SERVICE_CONTROL_POLICY', 'TAG_POLICY', 'BACKUP_POLICY', 'AISERVICES_OPT_OUT_POLICY']
            
            for policy_type in policy_types:
                try:
                    next_token = None
                    while True:
                        if next_token:
                            response = self.organizations_client.list_policies(
                                Filter=policy_type,
                                NextToken=next_token
                            )
                        else:
                            response = self.organizations_client.list_policies(Filter=policy_type)
                        
                        for policy in response.get('Policies', []):
                            # 获取策略详细信息
                            policy_detail = self.organizations_client.describe_policy(
                                PolicyId=policy['Id']
                            )
                            
                            # 获取策略的标签
                            tags = []
                            try:
                                tags_response = self.organizations_client.list_tags_for_resource(
                                    ResourceId=policy['Id']
                                )
                                tags = tags_response.get('Tags', [])
                            except Exception as e:
                                logger.warning(f"获取策略 {policy['Id']} 标签失败: {str(e)}")

                            # 获取策略目标
                            targets = []
                            try:
                                targets_response = self.organizations_client.list_targets_for_policy(
                                    PolicyId=policy['Id']
                                )
                                targets = targets_response.get('Targets', [])
                            except Exception as e:
                                logger.warning(f"获取策略 {policy['Id']} 目标失败: {str(e)}")

                            policy_info = {
                                'Id': policy_detail['Policy'].get('Id'),
                                'Arn': policy_detail['Policy'].get('Arn'),
                                'Name': policy_detail['Policy'].get('Name'),
                                'Description': policy_detail['Policy'].get('Description'),
                                'Type': policy_detail['Policy'].get('Type'),
                                'AwsManaged': policy_detail['Policy'].get('AwsManaged'),
                                'Content': policy_detail['Policy'].get('Content'),
                                'Summary': policy_detail['Policy'].get('Summary'),
                                'Tags': tags,
                                'Targets': targets
                            }
                            all_policies.append(policy_info)
                        
                        if 'NextToken' in response:
                            next_token = response['NextToken']
                        else:
                            break
                            
                except Exception as e:
                    logger.warning(f"获取策略类型 {policy_type} 失败: {str(e)}")

        except Exception as e:
            logger.error(f"获取策略信息失败: {str(e)}")

        return all_policies

    def get_handshakes(self) -> List[Dict[str, Any]]:
        """
        获取组织握手信息

        Returns:
            List[Dict[str, Any]]: 握手列表
        """
        logger.info("获取AWS Organizations握手信息")
        handshakes = []

        try:
            next_token = None
            while True:
                if next_token:
                    response = self.organizations_client.list_handshakes_for_organization(NextToken=next_token)
                else:
                    response = self.organizations_client.list_handshakes_for_organization()
                
                for handshake in response.get('Handshakes', []):
                    handshake_info = {
                        'Id': handshake.get('Id'),
                        'Arn': handshake.get('Arn'),
                        'Parties': handshake.get('Parties'),
                        'State': handshake.get('State'),
                        'RequestedTimestamp': handshake.get('RequestedTimestamp'),
                        'ExpirationTimestamp': handshake.get('ExpirationTimestamp'),
                        'Action': handshake.get('Action'),
                        'Resources': handshake.get('Resources')
                    }
                    handshakes.append(handshake_info)
                
                if 'NextToken' in response:
                    next_token = response['NextToken']
                else:
                    break

        except Exception as e:
            logger.error(f"获取握手信息失败: {str(e)}")

        return handshakes

    def get_delegated_administrators(self) -> List[Dict[str, Any]]:
        """
        获取委托管理员信息

        Returns:
            List[Dict[str, Any]]: 委托管理员列表
        """
        logger.info("获取AWS Organizations委托管理员信息")
        delegated_admins = []

        try:
            next_token = None
            while True:
                if next_token:
                    response = self.organizations_client.list_delegated_administrators(NextToken=next_token)
                else:
                    response = self.organizations_client.list_delegated_administrators()
                
                for admin in response.get('DelegatedAdministrators', []):
                    admin_info = {
                        'Id': admin.get('Id'),
                        'Arn': admin.get('Arn'),
                        'Email': admin.get('Email'),
                        'Name': admin.get('Name'),
                        'Status': admin.get('Status'),
                        'JoinedMethod': admin.get('JoinedMethod'),
                        'JoinedTimestamp': admin.get('JoinedTimestamp'),
                        'DelegationEnabledDate': admin.get('DelegationEnabledDate')
                    }
                    delegated_admins.append(admin_info)
                
                if 'NextToken' in response:
                    next_token = response['NextToken']
                else:
                    break

        except Exception as e:
            logger.error(f"获取委托管理员信息失败: {str(e)}")

        return delegated_admins

    def get_aws_service_access(self) -> List[Dict[str, Any]]:
        """
        获取AWS服务访问信息

        Returns:
            List[Dict[str, Any]]: AWS服务访问列表
        """
        logger.info("获取AWS Organizations服务访问信息")
        service_access = []

        try:
            next_token = None
            while True:
                if next_token:
                    response = self.organizations_client.list_aws_service_access_for_organization(NextToken=next_token)
                else:
                    response = self.organizations_client.list_aws_service_access_for_organization()
                
                for service in response.get('EnabledServicePrincipals', []):
                    service_info = {
                        'ServicePrincipal': service.get('ServicePrincipal'),
                        'DateEnabled': service.get('DateEnabled')
                    }
                    service_access.append(service_info)
                
                if 'NextToken' in response:
                    next_token = response['NextToken']
                else:
                    break

        except Exception as e:
            logger.error(f"获取AWS服务访问信息失败: {str(e)}")

        return service_access

    def get_all_organizations_global_assets(self) -> Dict[str, Any]:
        """
        获取所有Organizations全局资源

        Returns:
            Dict[str, Any]: 所有Organizations全局资源
        """
        logger.info("开始收集所有Organizations全局资源")
        
        assets = {
            'organization': self.get_organization(),
            'accounts': self.get_accounts(),
            'roots': self.get_roots(),
            'organizational_units': self.get_organizational_units(),
            'policies': self.get_policies(),
            'handshakes': self.get_handshakes(),
            'delegated_administrators': self.get_delegated_administrators(),
            'aws_service_access': self.get_aws_service_access()
        }
        
        logger.info("Organizations全局资源收集完成")
        return assets 