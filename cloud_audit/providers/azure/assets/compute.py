"""Azure计算资源收集器"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ComputeAssetCollector:
    """Azure计算资源收集器"""
    
    def __init__(self, session):
        """
        初始化计算资源收集器
        
        Args:
            session: Azure会话对象
        """
        self.session = session
        self.compute_client = session.get_client('compute')
    
    def get_virtual_machines(self) -> Dict[str, Any]:
        """
        获取虚拟机列表
        
        Returns:
            Dict[str, Any]: 虚拟机信息字典，键为虚拟机ID
        """
        try:
            vms = {}
            # 获取所有资源组
            resource_client = self.session.get_client('resource')
            resource_groups = resource_client.resource_groups.list()
            
            for rg in resource_groups:
                try:
                    for vm in self.compute_client.virtual_machines.list(resource_group_name=rg.name):
                        vm_dict = {
                            'id': vm.id,
                            'name': vm.name,
                            'location': vm.location,
                            'resource_group': vm.id.split('/')[4] if vm.id else None,
                            'vm_size': vm.hardware_profile.vm_size if vm.hardware_profile else None,
                            'os_type': vm.storage_profile.os_disk.os_type if vm.storage_profile and vm.storage_profile.os_disk else None,
                            'provisioning_state': vm.provisioning_state,
                            'power_state': None,  # 需要单独获取
                            'tags': dict(vm.tags) if vm.tags else {},
                            'network_interfaces': []
                        }
                        
                        # 获取网络接口信息
                        if vm.network_profile and vm.network_profile.network_interfaces:
                            for nic_ref in vm.network_profile.network_interfaces:
                                vm_dict['network_interfaces'].append({
                                    'id': nic_ref.id,
                                    'primary': nic_ref.primary
                                })
                        
                        # 获取电源状态
                        try:
                            resource_group = vm.id.split('/')[4]
                            instance_view = self.compute_client.virtual_machines.instance_view(
                                resource_group_name=resource_group,
                                vm_name=vm.name
                            )
                            if instance_view.statuses:
                                for status in instance_view.statuses:
                                    if status.code.startswith('PowerState/'):
                                        vm_dict['power_state'] = status.code.replace('PowerState/', '')
                                        break
                        except Exception as e:
                            logger.warning(f"获取VM {vm.name} 电源状态失败: {str(e)}")
                        
                        vms[vm.id] = vm_dict
                except Exception as e:
                    logger.debug(f"获取资源组 {rg.name} 的虚拟机失败: {str(e)}")
                    continue
            
            logger.info(f"获取到 {len(vms)} 个虚拟机")
            return vms
            
        except Exception as e:
            logger.error(f"获取虚拟机列表失败: {str(e)}")
            return {}
    
    def get_virtual_machine_scale_sets(self) -> Dict[str, Any]:
        """
        获取虚拟机规模集列表
        
        Returns:
            Dict[str, Any]: 虚拟机规模集信息字典，键为规模集ID
        """
        try:
            vmss_dict = {}
            # 获取所有资源组
            resource_client = self.session.get_client('resource')
            resource_groups = resource_client.resource_groups.list()
            
            for rg in resource_groups:
                try:
                    for vmss in self.compute_client.virtual_machine_scale_sets.list(resource_group_name=rg.name):
                        vmss_info = {
                            'id': vmss.id,
                            'name': vmss.name,
                            'location': vmss.location,
                            'resource_group': vmss.id.split('/')[4] if vmss.id else None,
                            'sku': {
                                'name': vmss.sku.name,
                                'tier': vmss.sku.tier,
                                'capacity': vmss.sku.capacity
                            } if vmss.sku else None,
                            'provisioning_state': vmss.provisioning_state,
                            'upgrade_policy': vmss.upgrade_policy.mode if vmss.upgrade_policy else None,
                            'tags': dict(vmss.tags) if vmss.tags else {}
                        }
                        vmss_dict[vmss.id] = vmss_info
                except Exception as e:
                    logger.debug(f"获取资源组 {rg.name} 的虚拟机规模集失败: {str(e)}")
                    continue
            
            logger.info(f"获取到 {len(vmss_dict)} 个虚拟机规模集")
            return vmss_dict
            
        except Exception as e:
            logger.error(f"获取虚拟机规模集列表失败: {str(e)}")
            return {}
    
    def get_availability_sets(self) -> Dict[str, Any]:
        """
        获取可用性集列表
        
        Returns:
            Dict[str, Any]: 可用性集信息字典，键为可用性集ID
        """
        try:
            availability_sets = {}
            # 获取所有资源组
            resource_client = self.session.get_client('resource')
            resource_groups = resource_client.resource_groups.list()
            
            for rg in resource_groups:
                try:
                    for avset in self.compute_client.availability_sets.list(resource_group_name=rg.name):
                        avset_dict = {
                            'id': avset.id,
                            'name': avset.name,
                            'location': avset.location,
                            'resource_group': avset.id.split('/')[4] if avset.id else None,
                            'platform_fault_domain_count': avset.platform_fault_domain_count,
                            'platform_update_domain_count': avset.platform_update_domain_count,
                            'sku': avset.sku.name if avset.sku else None,
                            'virtual_machines': [vm.id for vm in avset.virtual_machines] if avset.virtual_machines else [],
                            'tags': dict(avset.tags) if avset.tags else {}
                        }
                        availability_sets[avset.id] = avset_dict
                except Exception as e:
                    logger.debug(f"获取资源组 {rg.name} 的可用性集失败: {str(e)}")
                    continue
            
            logger.info(f"获取到 {len(availability_sets)} 个可用性集")
            return availability_sets
            
        except Exception as e:
            logger.error(f"获取可用性集列表失败: {str(e)}")
            return {}
    
    def get_disks(self) -> Dict[str, Any]:
        """
        获取磁盘列表
        
        Returns:
            Dict[str, Any]: 磁盘信息字典，键为磁盘ID
        """
        try:
            disks = {}
            for disk in self.compute_client.disks.list():
                disk_dict = {
                    'id': disk.id,
                    'name': disk.name,
                    'location': disk.location,
                    'resource_group': disk.id.split('/')[4] if disk.id else None,
                    'disk_size_gb': disk.disk_size_gb,
                    'disk_state': disk.disk_state,
                    'os_type': disk.os_type,
                    'creation_data': {
                        'create_option': disk.creation_data.create_option,
                        'source_uri': disk.creation_data.source_uri
                    } if disk.creation_data else None,
                    'sku': disk.sku.name if disk.sku else None,
                    'managed_by': disk.managed_by,
                    'tags': dict(disk.tags) if disk.tags else {}
                }
                disks[disk.id] = disk_dict
            
            logger.info(f"获取到 {len(disks)} 个磁盘")
            return disks
            
        except Exception as e:
            logger.error(f"获取磁盘列表失败: {str(e)}")
            return {}
    
    def get_snapshots(self) -> Dict[str, Any]:
        """
        获取快照列表
        
        Returns:
            Dict[str, Any]: 快照信息字典，键为快照ID
        """
        try:
            snapshots = {}
            for snapshot in self.compute_client.snapshots.list():
                snapshot_dict = {
                    'id': snapshot.id,
                    'name': snapshot.name,
                    'location': snapshot.location,
                    'resource_group': snapshot.id.split('/')[4] if snapshot.id else None,
                    'disk_size_gb': snapshot.disk_size_gb,
                    'os_type': snapshot.os_type,
                    'creation_data': {
                        'create_option': snapshot.creation_data.create_option,
                        'source_uri': snapshot.creation_data.source_uri
                    } if snapshot.creation_data else None,
                    'sku': snapshot.sku.name if snapshot.sku else None,
                    'time_created': snapshot.time_created.isoformat() if snapshot.time_created else None,
                    'tags': dict(snapshot.tags) if snapshot.tags else {}
                }
                snapshots[snapshot.id] = snapshot_dict
            
            logger.info(f"获取到 {len(snapshots)} 个快照")
            return snapshots
            
        except Exception as e:
            logger.error(f"获取快照列表失败: {str(e)}")
            return {}
    
    def get_all_compute_assets(self) -> Dict[str, Any]:
        """
        获取所有计算资源
        
        Returns:
            Dict[str, Any]: 所有计算资源信息
        """
        logger.info("开始收集Azure计算资源")
        
        compute_assets = {
            'virtual_machines': self.get_virtual_machines(),
            'virtual_machine_scale_sets': self.get_virtual_machine_scale_sets(),
            'availability_sets': self.get_availability_sets(),
            'disks': self.get_disks(),
            'snapshots': self.get_snapshots()
        }
        
        # 统计信息
        total_count = sum(len(assets) for assets in compute_assets.values())
        logger.info(f"Azure计算资源收集完成，共 {total_count} 个资源")
        
        return compute_assets 