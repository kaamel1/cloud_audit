"""Azure Key Vault资源收集器"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class KeyVaultAssetCollector:
    """Azure Key Vault资源收集器"""
    
    def __init__(self, session):
        """
        初始化Key Vault资源收集器
        
        Args:
            session: Azure会话对象
        """
        self.session = session
        try:
            self.keyvault_client = session.get_client('keyvault')
        except Exception as e:
            logger.warning(f"无法初始化Key Vault客户端: {str(e)}")
            self.keyvault_client = None
    
    def get_vaults(self) -> Dict[str, Any]:
        """
        获取Key Vault列表
        
        Returns:
            Dict[str, Any]: Key Vault信息字典，键为Key Vault ID
        """
        if not self.keyvault_client:
            logger.warning("Key Vault客户端未初始化，跳过Key Vault收集")
            return {}
            
        try:
            vaults = {}
            for vault in self.keyvault_client.vaults.list():
                vault_dict = {
                    'id': vault.id,
                    'name': vault.name,
                    'location': vault.location,
                    'resource_group': vault.id.split('/')[4] if vault.id else None,
                    'vault_uri': vault.properties.vault_uri if vault.properties else None,
                    'tenant_id': vault.properties.tenant_id if vault.properties else None,
                    'sku': {
                        'family': vault.properties.sku.family,
                        'name': vault.properties.sku.name
                    } if vault.properties and vault.properties.sku else None,
                    'enabled_for_deployment': vault.properties.enabled_for_deployment if vault.properties else None,
                    'enabled_for_disk_encryption': vault.properties.enabled_for_disk_encryption if vault.properties else None,
                    'enabled_for_template_deployment': vault.properties.enabled_for_template_deployment if vault.properties else None,
                    'enable_soft_delete': vault.properties.enable_soft_delete if vault.properties else None,
                    'soft_delete_retention_in_days': vault.properties.soft_delete_retention_in_days if vault.properties else None,
                    'enable_purge_protection': vault.properties.enable_purge_protection if vault.properties else None,
                    'access_policies': [],
                    'tags': dict(vault.tags) if vault.tags else {}
                }
                
                # 获取访问策略
                if vault.properties and vault.properties.access_policies:
                    for policy in vault.properties.access_policies:
                        policy_dict = {
                            'tenant_id': policy.tenant_id,
                            'object_id': policy.object_id,
                            'application_id': policy.application_id,
                            'permissions': {
                                'keys': policy.permissions.keys or [],
                                'secrets': policy.permissions.secrets or [],
                                'certificates': policy.permissions.certificates or [],
                                'storage': policy.permissions.storage or []
                            } if policy.permissions else {}
                        }
                        vault_dict['access_policies'].append(policy_dict)
                
                vaults[vault.id] = vault_dict
            
            logger.info(f"获取到 {len(vaults)} 个Key Vault")
            return vaults
            
        except Exception as e:
            logger.error(f"获取Key Vault失败: {str(e)}")
            return {}
    
    def get_all_keyvault_assets(self) -> Dict[str, Any]:
        """
        获取所有Key Vault资源
        
        Returns:
            Dict[str, Any]: 所有Key Vault资源信息
        """
        logger.info("开始收集Azure Key Vault资源")
        
        keyvault_assets = {
            'vaults': self.get_vaults()
        }
        
        # 统计信息
        total_count = sum(len(assets) for assets in keyvault_assets.values())
        logger.info(f"Azure Key Vault资源收集完成，共 {total_count} 个资源")
        
        return keyvault_assets 