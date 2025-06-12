"""Azure IAM资源收集器"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class IAMAssetCollector:
    """Azure IAM资源收集器"""
    
    def __init__(self, session):
        """
        初始化IAM资源收集器
        
        Args:
            session: Azure会话对象
        """
        self.session = session
        try:
            self.authorization_client = session.get_client('authorization')
        except Exception as e:
            logger.warning(f"无法初始化授权客户端: {str(e)}")
            self.authorization_client = None
    
    def get_role_definitions(self) -> Dict[str, Any]:
        """
        获取角色定义列表
        
        Returns:
            Dict[str, Any]: 角色定义信息字典，键为角色定义ID
        """
        if not self.authorization_client:
            logger.warning("授权客户端未初始化，跳过角色定义收集")
            return {}
            
        try:
            role_definitions = {}
            scope = f"/subscriptions/{self.session.get_subscription_id()}"
            
            for role_def in self.authorization_client.role_definitions.list(scope=scope):
                role_dict = {
                    'id': role_def.id,
                    'name': role_def.name,
                    'role_name': role_def.role_name,
                    'description': role_def.description,
                    'role_type': role_def.role_type,
                    'permissions': [],
                    'assignable_scopes': role_def.assignable_scopes or []
                }
                
                # 获取权限信息
                if role_def.permissions:
                    for permission in role_def.permissions:
                        perm_dict = {
                            'actions': permission.actions or [],
                            'not_actions': permission.not_actions or [],
                            'data_actions': permission.data_actions or [],
                            'not_data_actions': permission.not_data_actions or []
                        }
                        role_dict['permissions'].append(perm_dict)
                
                role_definitions[role_def.id] = role_dict
            
            logger.info(f"获取到 {len(role_definitions)} 个角色定义")
            return role_definitions
            
        except Exception as e:
            logger.error(f"获取角色定义失败: {str(e)}")
            return {}
    
    def get_role_assignments(self) -> Dict[str, Any]:
        """
        获取角色分配列表
        
        Returns:
            Dict[str, Any]: 角色分配信息字典，键为角色分配ID
        """
        if not self.authorization_client:
            logger.warning("授权客户端未初始化，跳过角色分配收集")
            return {}
            
        try:
            role_assignments = {}
            
            scope = f"/subscriptions/{self.session.get_subscription_id()}"
            for assignment in self.authorization_client.role_assignments.list(scope=scope):
                assignment_dict = {
                    'id': assignment.id,
                    'name': assignment.name,
                    'scope': assignment.scope,
                    'role_definition_id': assignment.role_definition_id,
                    'principal_id': assignment.principal_id,
                    'principal_type': assignment.principal_type,
                    'can_delegate': assignment.can_delegate
                }
                role_assignments[assignment.id] = assignment_dict
            
            logger.info(f"获取到 {len(role_assignments)} 个角色分配")
            return role_assignments
            
        except Exception as e:
            logger.error(f"获取角色分配失败: {str(e)}")
            return {}
    
    def get_all_iam_assets(self) -> Dict[str, Any]:
        """
        获取所有IAM资源
        
        Returns:
            Dict[str, Any]: 所有IAM资源信息
        """
        logger.info("开始收集Azure IAM资源")
        
        iam_assets = {
            'role_definitions': self.get_role_definitions(),
            'role_assignments': self.get_role_assignments()
        }
        
        # 统计信息
        total_count = sum(len(assets) for assets in iam_assets.values())
        logger.info(f"Azure IAM资源收集完成，共 {total_count} 个资源")
        
        return iam_assets 