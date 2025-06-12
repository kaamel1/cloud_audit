"""Azure存储资源收集器"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class StorageAssetCollector:
    """Azure存储资源收集器"""
    
    def __init__(self, session):
        """
        初始化存储资源收集器
        
        Args:
            session: Azure会话对象
        """
        self.session = session
        self.storage_client = session.get_client('storage')
    
    def get_storage_accounts(self) -> Dict[str, Any]:
        """
        获取存储账户列表
        
        Returns:
            Dict[str, Any]: 存储账户信息字典，键为存储账户ID
        """
        try:
            storage_accounts = {}
            for account in self.storage_client.storage_accounts.list():
                account_dict = {
                    'id': account.id,
                    'name': account.name,
                    'location': account.location,
                    'resource_group': account.id.split('/')[4] if account.id else None,
                    'kind': account.kind,
                    'sku': {
                        'name': account.sku.name,
                        'tier': account.sku.tier
                    } if account.sku else None,
                    'access_tier': account.access_tier,
                    'provisioning_state': account.provisioning_state,
                    'primary_location': account.primary_location,
                    'secondary_location': account.secondary_location,
                    'status_of_primary': account.status_of_primary,
                    'status_of_secondary': account.status_of_secondary,
                    'creation_time': account.creation_time.isoformat() if account.creation_time else None,
                    'custom_domain': {
                        'name': account.custom_domain.name,
                        'use_sub_domain': account.custom_domain.use_sub_domain_name
                    } if account.custom_domain else None,
                    'encryption': {
                        'services': {},
                        'key_source': account.encryption.key_source
                    } if account.encryption else None,
                    'network_rule_set': {
                        'default_action': account.network_rule_set.default_action,
                        'bypass': account.network_rule_set.bypass
                    } if account.network_rule_set else None,
                    'enable_https_traffic_only': account.enable_https_traffic_only,
                    'tags': dict(account.tags) if account.tags else {}
                }
                
                # 获取加密服务信息
                if account.encryption and account.encryption.services:
                    if account.encryption.services.blob:
                        account_dict['encryption']['services']['blob'] = {
                            'enabled': account.encryption.services.blob.enabled,
                            'last_enabled_time': account.encryption.services.blob.last_enabled_time.isoformat() if account.encryption.services.blob.last_enabled_time else None
                        }
                    if account.encryption.services.file:
                        account_dict['encryption']['services']['file'] = {
                            'enabled': account.encryption.services.file.enabled,
                            'last_enabled_time': account.encryption.services.file.last_enabled_time.isoformat() if account.encryption.services.file.last_enabled_time else None
                        }
                
                storage_accounts[account.id] = account_dict
            
            logger.info(f"获取到 {len(storage_accounts)} 个存储账户")
            return storage_accounts
            
        except Exception as e:
            logger.error(f"获取存储账户列表失败: {str(e)}")
            return {}
    
    def get_blob_containers(self) -> Dict[str, Any]:
        """
        获取Blob容器列表
        
        Returns:
            Dict[str, Any]: Blob容器信息字典，键为容器ID
        """
        try:
            containers = {}
            
            # 首先获取所有存储账户
            for account in self.storage_client.storage_accounts.list():
                try:
                    resource_group = account.id.split('/')[4]
                    
                    # 获取该存储账户下的所有容器
                    blob_containers = self.storage_client.blob_containers.list(
                        resource_group_name=resource_group,
                        account_name=account.name
                    )
                    
                    for container in blob_containers:
                        container_dict = {
                            'id': container.id,
                            'name': container.name,
                            'storage_account': account.name,
                            'resource_group': resource_group,
                            'public_access': container.public_access,
                            'last_modified_time': container.last_modified_time.isoformat() if container.last_modified_time else None,
                            'lease_status': container.lease_status,
                            'lease_state': container.lease_state,
                            'has_immutability_policy': container.has_immutability_policy,
                            'has_legal_hold': container.has_legal_hold,
                            'metadata': dict(container.metadata) if container.metadata else {}
                        }
                        containers[container.id] = container_dict
                        
                except Exception as e:
                    logger.warning(f"获取存储账户 {account.name} 的容器失败: {str(e)}")
                    continue
            
            logger.info(f"获取到 {len(containers)} 个Blob容器")
            return containers
            
        except Exception as e:
            logger.error(f"获取Blob容器列表失败: {str(e)}")
            return {}
    
    def get_file_shares(self) -> Dict[str, Any]:
        """
        获取文件共享列表
        
        Returns:
            Dict[str, Any]: 文件共享信息字典，键为文件共享ID
        """
        try:
            file_shares = {}
            
            # 首先获取所有存储账户
            for account in self.storage_client.storage_accounts.list():
                try:
                    resource_group = account.id.split('/')[4]
                    
                    # 获取该存储账户下的所有文件共享
                    shares = self.storage_client.file_shares.list(
                        resource_group_name=resource_group,
                        account_name=account.name
                    )
                    
                    for share in shares:
                        share_dict = {
                            'id': share.id,
                            'name': share.name,
                            'storage_account': account.name,
                            'resource_group': resource_group,
                            'quota': share.share_quota,
                            'last_modified_time': share.last_modified_time.isoformat() if share.last_modified_time else None,
                            'metadata': dict(share.metadata) if share.metadata else {}
                        }
                        file_shares[share.id] = share_dict
                        
                except Exception as e:
                    logger.warning(f"获取存储账户 {account.name} 的文件共享失败: {str(e)}")
                    continue
            
            logger.info(f"获取到 {len(file_shares)} 个文件共享")
            return file_shares
            
        except Exception as e:
            logger.error(f"获取文件共享列表失败: {str(e)}")
            return {}
    
    def get_storage_account_keys(self) -> Dict[str, Any]:
        """
        获取存储账户密钥信息（仅获取密钥元数据，不获取实际密钥值）
        
        Returns:
            Dict[str, Any]: 存储账户密钥信息字典，键为存储账户名称
        """
        try:
            account_keys_info = {}
            
            # 获取所有存储账户
            for account in self.storage_client.storage_accounts.list():
                try:
                    resource_group = account.id.split('/')[4]
                    
                    # 获取密钥列表（仅获取元数据）
                    keys = self.storage_client.storage_accounts.list_keys(
                        resource_group_name=resource_group,
                        account_name=account.name
                    )
                    
                    key_info = {
                        'storage_account': account.name,
                        'resource_group': resource_group,
                        'key_count': len(keys.keys) if keys.keys else 0,
                        'key_names': [key.key_name for key in keys.keys] if keys.keys else []
                    }
                    account_keys_info[account.name] = key_info
                    
                except Exception as e:
                    logger.warning(f"获取存储账户 {account.name} 的密钥信息失败: {str(e)}")
                    continue
            
            logger.info(f"获取到 {len(account_keys_info)} 个存储账户的密钥信息")
            return account_keys_info
            
        except Exception as e:
            logger.error(f"获取存储账户密钥信息失败: {str(e)}")
            return {}
    
    def get_all_storage_assets(self) -> Dict[str, Any]:
        """
        获取所有存储资源
        
        Returns:
            Dict[str, Any]: 所有存储资源信息
        """
        logger.info("开始收集Azure存储资源")
        
        storage_assets = {
            'storage_accounts': self.get_storage_accounts(),
            'blob_containers': self.get_blob_containers(),
            'file_shares': self.get_file_shares(),
            'storage_account_keys': self.get_storage_account_keys()
        }
        
        # 统计信息
        total_count = sum(len(assets) for assets in storage_assets.values())
        logger.info(f"Azure存储资源收集完成，共 {total_count} 个资源")
        
        return storage_assets 