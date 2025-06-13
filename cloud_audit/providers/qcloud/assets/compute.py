"""
腾讯云计算资产收集器

负责收集腾讯云的各种计算资源，包括：
- 云服务器 (CVM)
- 轻量应用服务器 (Lighthouse)
- 容器服务 (TKE)
- 云函数 (SCF)
- 弹性伸缩 (AS)
"""

import logging
from typing import Dict, Any, List
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.cvm.v20170312 import models as cvm_models
from tencentcloud.lighthouse.v20200324 import models as lighthouse_models  
from tencentcloud.tke.v20180525 import models as tke_models
from tencentcloud.scf.v20180416 import models as scf_models

logger = logging.getLogger(__name__)

class ComputeAssetCollector:
    """计算资产收集器"""
    
    def __init__(self, session):
        """
        初始化计算资产收集器
        
        Args:
            session: 腾讯云会话对象
        """
        self.session = session
        
    def get_all_compute_assets(self) -> Dict[str, Any]:
        """
        获取所有计算资产
        
        Returns:
            Dict[str, Any]: 包含所有计算资产的字典
        """
        logger.info("开始收集腾讯云计算资产")
        
        assets = {
            'cvm_instances': self.get_cvm_instances(),
            'lighthouse_instances': self.get_lighthouse_instances(),
            'tke_clusters': self.get_tke_clusters(),
            'scf_functions': self.get_scf_functions(),
            'images': self.get_images(),
            'key_pairs': self.get_key_pairs(),
        }
        
        logger.info("腾讯云计算资产收集完成")
        return assets
    
    def get_cvm_instances(self) -> List[Dict[str, Any]]:
        """
        获取CVM实例列表
        
        Returns:
            List[Dict[str, Any]]: CVM实例列表
        """
        logger.info("收集CVM实例")
        instances = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            cvm_client = self.session.get_client('cvm', region=region)
            req = cvm_models.DescribeInstancesRequest()
            
            # 分页获取所有实例
            offset = 0
            limit = 100
            
            while True:
                req.Offset = offset
                req.Limit = limit
                
                resp = cvm_client.DescribeInstances(req)
                
                if not resp.InstanceSet:
                    break
                    
                for instance in resp.InstanceSet:
                    instance_info = {
                        'region': region,
                        'instance_id': instance.InstanceId,
                        'instance_name': instance.InstanceName,
                        'instance_type': instance.InstanceType,
                        'instance_state': instance.InstanceState,
                        'image_id': instance.ImageId,
                        'placement': {
                            'zone': instance.Placement.Zone,
                            'project_id': instance.Placement.ProjectId,
                        } if instance.Placement else None,
                        'private_ip_addresses': instance.PrivateIpAddresses if instance.PrivateIpAddresses else [],
                        'public_ip_addresses': instance.PublicIpAddresses if instance.PublicIpAddresses else [],
                        'vpc_id': instance.VirtualPrivateCloud.VpcId if instance.VirtualPrivateCloud else None,
                        'subnet_id': instance.VirtualPrivateCloud.SubnetId if instance.VirtualPrivateCloud else None,
                        'security_group_ids': instance.SecurityGroupIds,
                        'instance_charge_type': instance.InstanceChargeType,
                        'internet_charge_type': instance.InternetAccessible.InternetChargeType if instance.InternetAccessible else None,
                        'internet_max_bandwidth_out': instance.InternetAccessible.InternetMaxBandwidthOut if instance.InternetAccessible else None,
                        'system_disk': {
                            'disk_type': instance.SystemDisk.DiskType,
                            'disk_id': instance.SystemDisk.DiskId,
                            'disk_size': instance.SystemDisk.DiskSize,
                        } if instance.SystemDisk else None,
                        'data_disks': [
                            {
                                'disk_type': disk.DiskType,
                                'disk_id': disk.DiskId,
                                'disk_size': disk.DiskSize,
                            } for disk in instance.DataDisks
                        ] if instance.DataDisks else [],
                        'tags': [
                            {
                                'key': tag.Key,
                                'value': tag.Value,
                            } for tag in instance.Tags
                        ] if instance.Tags else [],
                        'created_time': instance.CreatedTime,
                        'expired_time': instance.ExpiredTime,
                    }
                    instances.append(instance_info)
                
                offset += limit
                if len(resp.InstanceSet) < limit:
                    break
                    
        except Exception as e:
            logger.error(f"获取CVM实例时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(instances)} 个CVM实例")
        return instances
    
    def get_lighthouse_instances(self) -> List[Dict[str, Any]]:
        """
        获取轻量应用服务器实例列表
        
        Returns:
            List[Dict[str, Any]]: 轻量应用服务器实例列表
        """
        logger.info("收集轻量应用服务器实例")
        instances = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            lighthouse_client = self.session.get_client('lighthouse', region=region)
            req = lighthouse_models.DescribeInstancesRequest()
            
            resp = lighthouse_client.DescribeInstances(req)
            
            if resp.InstanceSet:
                for instance in resp.InstanceSet:
                    instance_info = {
                        'region': region,
                        'instance_id': instance.InstanceId,
                        'instance_name': instance.InstanceName,
                        'instance_state': instance.InstanceState,
                        'bundle_id': instance.BundleId,
                        'blueprint_id': instance.BlueprintId,
                        'zone': instance.Zone,
                        'platform_type': instance.PlatformType,
                        'private_addresses': instance.PrivateAddresses,
                        'public_addresses': instance.PublicAddresses,
                        'internet_accessible': {
                            'internet_charge_type': instance.InternetAccessible.InternetChargeType,
                            'internet_max_bandwidth_out': instance.InternetAccessible.InternetMaxBandwidthOut,
                            'public_ip_assigned': instance.InternetAccessible.PublicIpAssigned,
                        } if instance.InternetAccessible else None,
                        'created_time': instance.CreatedTime,
                        'expired_time': instance.ExpiredTime,
                    }
                    instances.append(instance_info)
                    
        except Exception as e:
            logger.error(f"获取轻量应用服务器实例时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(instances)} 个轻量应用服务器实例")
        return instances
    
    def get_tke_clusters(self) -> List[Dict[str, Any]]:
        """
        获取TKE集群列表
        
        Returns:
            List[Dict[str, Any]]: TKE集群列表
        """
        logger.info("收集TKE集群")
        clusters = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            tke_client = self.session.get_client('tke', region=region)
            req = tke_models.DescribeClustersRequest()
            
            resp = tke_client.DescribeClusters(req)
            
            if resp.Clusters:
                for cluster in resp.Clusters:
                    cluster_info = {
                        'region': region,
                        'cluster_id': cluster.ClusterId,
                        'cluster_name': cluster.ClusterName,
                        'cluster_description': cluster.ClusterDescription,
                        'cluster_version': cluster.ClusterVersion,
                        'cluster_os': cluster.ClusterOs,
                        'cluster_type': cluster.ClusterType,
                        'cluster_network_settings': {
                            'cluster_cidr': cluster.ClusterNetworkSettings.ClusterCIDR,
                            'ignore_cluster_cidr_conflict': cluster.ClusterNetworkSettings.IgnoreClusterCIDRConflict,
                            'max_node_pod_num': cluster.ClusterNetworkSettings.MaxNodePodNum,
                            'max_cluster_service_num': cluster.ClusterNetworkSettings.MaxClusterServiceNum,
                        } if cluster.ClusterNetworkSettings else None,
                        'cluster_status': cluster.ClusterStatus,
                        'cluster_advanced_settings': {
                            'ipvs': cluster.ClusterAdvancedSettings.IPVS,
                            'as_enabled': cluster.ClusterAdvancedSettings.AsEnabled,
                            'container_runtime': cluster.ClusterAdvancedSettings.ContainerRuntime,
                        } if cluster.ClusterAdvancedSettings else None,
                        'created_time': cluster.CreatedTime,
                    }
                    clusters.append(cluster_info)
                    
        except Exception as e:
            logger.error(f"获取TKE集群时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(clusters)} 个TKE集群")
        return clusters
    
    def get_scf_functions(self) -> List[Dict[str, Any]]:
        """
        获取云函数列表
        
        Returns:
            List[Dict[str, Any]]: 云函数列表
        """
        logger.info("收集云函数")
        functions = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            scf_client = self.session.get_client('scf', region=region)
            req = scf_models.ListFunctionsRequest()
            
            resp = scf_client.ListFunctions(req)
            
            if resp.Functions:
                for func in resp.Functions:
                    function_info = {
                        'region': region,
                        'function_name': func.FunctionName,
                        'function_id': func.FunctionId,
                        'namespace': func.Namespace,
                        'status': func.Status,
                        'status_desc': func.StatusDesc,
                        'description': func.Description,
                        'tags': [
                            {
                                'key': tag.Key,
                                'value': tag.Value,
                            } for tag in func.Tags
                        ] if func.Tags else [],
                        'type': func.Type,
                        'code_info': {
                            'code_size': func.CodeInfo.CodeSize,
                            'code_result': func.CodeInfo.CodeResult,
                            'code_error': func.CodeInfo.CodeError,
                        } if func.CodeInfo else None,
                        'add_time': func.AddTime,
                        'modify_time': func.ModTime,
                        'runtime': func.Runtime,
                    }
                    functions.append(function_info)
                    
        except Exception as e:
            logger.error(f"获取云函数时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(functions)} 个云函数")
        return functions
    
    def get_images(self) -> List[Dict[str, Any]]:
        """
        获取镜像列表
        
        Returns:
            List[Dict[str, Any]]: 镜像列表
        """
        logger.info("收集镜像")
        images = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            cvm_client = self.session.get_client('cvm', region=region)
            req = cvm_models.DescribeImagesRequest()
            
            # 添加过滤器，排除官方镜像 (image-source != OFFICIAL)
            # 注意：腾讯云API的过滤器是包含关系，我们需要指定要包含的类型
            # 非官方镜像的来源类型包括：CREATE_IMAGE（用户自建）、EXTERNAL_IMPORT（外部导入）等
            # filter_obj = cvm_models.Filter()
            # filter_obj.Name = "image-source"
            # filter_obj.Values = ["CREATE_IMAGE", "EXTERNAL_IMPORT"]  # 只包含自定义和外部导入的镜像
            # req.Filters = [filter_obj]
            
            resp = cvm_client.DescribeImages(req)
            
            if resp.ImageSet:
                for image in resp.ImageSet:
                    image_info = {
                        'region': region,
                        'image_id': image.ImageId,
                        'image_os_name': image.OsName,
                        'image_type': image.ImageType,
                        'image_create_time': image.CreatedTime,
                        'image_size': image.ImageSize,
                        'architecture': image.Architecture,
                        'image_state': image.ImageState,
                        'platform': image.Platform,
                        'image_creator': image.ImageCreator,
                        'image_source': image.ImageSource,
                    }
                    images.append(image_info)
                    
        except Exception as e:
            logger.error(f"获取镜像时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(images)} 个镜像")
        return images
    
    def get_key_pairs(self) -> List[Dict[str, Any]]:
        """
        获取密钥对列表
        
        Returns:
            List[Dict[str, Any]]: 密钥对列表
        """
        logger.info("收集密钥对")
        key_pairs = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            cvm_client = self.session.get_client('cvm', region=region)
            req = cvm_models.DescribeKeyPairsRequest()
            
            resp = cvm_client.DescribeKeyPairs(req)
            
            if resp.KeyPairSet:
                for key_pair in resp.KeyPairSet:
                    key_pair_info = {
                        'region': region,
                        'key_id': key_pair.KeyId,
                        'key_name': key_pair.KeyName,
                        'project_id': key_pair.ProjectId,
                        'description': key_pair.Description,
                        'public_key': key_pair.PublicKey,
                        'private_key': key_pair.PrivateKey,
                        'associated_instance_ids': key_pair.AssociatedInstanceIds,
                        'created_time': key_pair.CreatedTime,
                    }
                    key_pairs.append(key_pair_info)
                    
        except Exception as e:
            logger.error(f"获取密钥对时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(key_pairs)} 个密钥对")
        return key_pairs 