"""
AWS Organizations资源处理模块，负责获取组织、账户、组织单位、服务控制策略等企业级管理资源信息。
"""
import boto3
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class OrganizationsAssetCollector:
    """AWS Organizations资源收集器"""

    def __init__(self, session):
        """
        初始化Organizations资源收集器

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
            paginator = self.organizations_client.get_paginator('list_accounts')
            
            for page in paginator.paginate():
                for account in page.get('Accounts', []):
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
            paginator = self.organizations_client.get_paginator('list_roots')
            
            for page in paginator.paginate():
                for root in page.get('Roots', []):
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
            paginator = self.organizations_client.get_paginator('list_organizational_units_for_parent')
            
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page.get('OrganizationalUnits', []):
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

                    # 获取OU的子级账户
                    child_accounts = []
                    try:
                        children_paginator = self.organizations_client.get_paginator('list_accounts_for_parent')
                        for children_page in children_paginator.paginate(ParentId=ou['Id']):
                            child_accounts.extend(children_page.get('Accounts', []))
                    except Exception as e:
                        logger.warning(f"获取OU {ou['Id']} 子级账户失败: {str(e)}")

                    ou_info = {
                        'Id': ou.get('Id'),
                        'Arn': ou.get('Arn'),
                        'Name': ou.get('Name'),
                        'ParentId': parent_id,
                        'Tags': tags,
                        'PolicyTypes': policy_types,
                        'ChildAccounts': child_accounts
                    }
                    ous.append(ou_info)
                    
                    # 递归获取子级OU
                    child_ous = self._get_ous_recursive(ou['Id'])
                    ous.extend(child_ous)

        except Exception as e:
            logger.warning(f"获取父级 {parent_id} 的组织单位失败: {str(e)}")

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
                    paginator = self.organizations_client.get_paginator('list_policies')
                    
                    for page in paginator.paginate(Filter=policy_type):
                        for policy in page.get('Policies', []):
                            # 获取策略详细信息
                            policy_detail = self.organizations_client.describe_policy(
                                PolicyId=policy['Id']
                            )
                            
                            policy_info = policy_detail['Policy']
                            
                            # 获取策略标签
                            tags = []
                            try:
                                tags_response = self.organizations_client.list_tags_for_resource(
                                    ResourceId=policy['Id']
                                )
                                tags = tags_response.get('Tags', [])
                            except Exception as e:
                                logger.warning(f"获取策略 {policy['Id']} 标签失败: {str(e)}")

                            # 获取策略关联的目标
                            targets = []
                            try:
                                targets_paginator = self.organizations_client.get_paginator('list_targets_for_policy')
                                for targets_page in targets_paginator.paginate(PolicyId=policy['Id']):
                                    targets.extend(targets_page.get('Targets', []))
                            except Exception as e:
                                logger.warning(f"获取策略 {policy['Id']} 关联目标失败: {str(e)}")

                            enhanced_policy_info = {
                                'Id': policy_info.get('Id'),
                                'Arn': policy_info.get('Arn'),
                                'Name': policy_info.get('Name'),
                                'Description': policy_info.get('Description'),
                                'Type': policy_info.get('Type'),
                                'AwsManaged': policy_info.get('AwsManaged'),
                                'Content': policy_info.get('Content'),
                                'PolicySummary': policy_info.get('PolicySummary'),
                                'Tags': tags,
                                'Targets': targets
                            }
                            all_policies.append(enhanced_policy_info)
                            
                except Exception as e:
                    logger.warning(f"获取策略类型 {policy_type} 失败: {str(e)}")

        except Exception as e:
            logger.error(f"获取策略信息失败: {str(e)}")

        return all_policies

    def get_handshakes(self) -> List[Dict[str, Any]]:
        """
        获取组织邀请握手信息

        Returns:
            List[Dict[str, Any]]: 握手列表
        """
        logger.info("获取AWS Organizations握手信息")
        handshakes = []

        try:
            paginator = self.organizations_client.get_paginator('list_handshakes_for_organization')
            
            for page in paginator.paginate():
                for handshake in page.get('Handshakes', []):
                    handshake_info = {
                        'Id': handshake.get('Id'),
                        'Arn': handshake.get('Arn'),
                        'State': handshake.get('State'),
                        'RequestedTimestamp': handshake.get('RequestedTimestamp'),
                        'ExpirationTimestamp': handshake.get('ExpirationTimestamp'),
                        'Action': handshake.get('Action'),
                        'Resources': handshake.get('Resources', []),
                        'Parties': handshake.get('Parties', [])
                    }
                    handshakes.append(handshake_info)

        except Exception as e:
            logger.error(f"获取握手信息失败: {str(e)}")

        return handshakes

    def get_all_organizations_assets(self) -> Dict[str, Any]:
        """
        获取所有Organizations资源

        Returns:
            Dict[str, Any]: 所有Organizations资源
        """
        logger.info("获取所有AWS Organizations资源")
        
        organization = self.get_organization()
        
        # 如果没有组织，返回空结构
        if not organization:
            return {
                'organization': None,
                'accounts': [],
                'roots': [],
                'organizational_units': [],
                'policies': [],
                'handshakes': [],
                'summary': {
                    'has_organization': False,
                    'total_accounts': 0,
                    'total_ous': 0,
                    'total_policies': 0,
                    'total_handshakes': 0
                }
            }
        
        accounts = self.get_accounts()
        roots = self.get_roots()
        organizational_units = self.get_organizational_units()
        policies = self.get_policies()
        handshakes = self.get_handshakes()
        
        # 按类型分组策略
        policies_by_type = {}
        for policy in policies:
            policy_type = policy.get('Type', 'UNKNOWN')
            if policy_type not in policies_by_type:
                policies_by_type[policy_type] = []
            policies_by_type[policy_type].append(policy)
        
        # 按状态分组账户
        accounts_by_status = {}
        for account in accounts:
            status = account.get('Status', 'UNKNOWN')
            if status not in accounts_by_status:
                accounts_by_status[status] = []
            accounts_by_status[status].append(account)
        
        organizations_assets = {
            'organization': organization,
            'accounts': {account['Id']: account for account in accounts},
            'roots': {root['Id']: root for root in roots},
            'organizational_units': {ou['Id']: ou for ou in organizational_units},
            'policies': {policy['Id']: policy for policy in policies},
            'handshakes': handshakes,  # 保持列表格式
            'policies_by_type': policies_by_type,
            'accounts_by_status': accounts_by_status,
            'summary': {
                'has_organization': True,
                'organization_id': organization.get('Id'),
                'master_account_id': organization.get('MasterAccountId'),
                'feature_set': organization.get('FeatureSet'),
                'total_accounts': len(accounts),
                'total_roots': len(roots),
                'total_ous': len(organizational_units),
                'total_policies': len(policies),
                'total_handshakes': len(handshakes)
            }
        }
        
        logger.info(f"已获取组织信息, {len(accounts)} 个账户, {len(organizational_units)} 个OU, {len(policies)} 个策略, {len(handshakes)} 个握手")
        return organizations_assets 