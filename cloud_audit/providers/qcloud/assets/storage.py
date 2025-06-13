"""
腾讯云存储资产收集器

负责收集腾讯云的各种存储资源，包括：
- 对象存储 (COS) - 区域服务，增强版本包含：
  * 基本信息：桶名称、创建时间、区域
  * 访问控制：ACL配置、存储桶策略、公开读写检查
  * 跨域配置：CORS规则和状态
  * 域名配置：自定义域名、CDN域名绑定
  * 安全配置：加密设置、HTTPS强制、防盗链
  * 高级功能：版本控制、生命周期、静态网站、日志记录
  * 性能优化：传输加速配置
  * 标签管理：存储桶标签信息
  * 数据容灾：跨地区复制配置、目标桶信息、复制状态
- 云硬盘 (CBS) - 区域服务
- 文件存储 (CFS) - 区域服务

新增的 COS 详细信息收集功能：
1. 公开只读/写权限检查 - 通过 ACL 分析是否允许匿名用户访问
2. 访问控制策略 - 收集和解析存储桶策略 JSON
3. 跨域资源共享 - 获取 CORS 规则配置
4. 绑定域名信息 - 收集自定义域名和 CDN 域名配置
5. 强制 HTTPS 检查 - 通过策略和域名配置检查是否强制 HTTPS
6. 跨地区复制配置 - 收集复制规则、目标桶、复制状态和统计信息
7. 其他安全和管理配置 - 加密、版本控制、生命周期等
"""

import logging
from typing import Dict, Any, List
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.cbs.v20170312 import models as cbs_models
from tencentcloud.cfs.v20190719 import models as cfs_models

logger = logging.getLogger(__name__)

class StorageAssetCollector:
    """存储资产收集器"""
    
    def __init__(self, session):
        """
        初始化存储资产收集器
        
        Args:
            session: 腾讯云会话对象
        """
        self.session = session
        
    def get_all_storage_assets(self) -> Dict[str, Any]:
        """
        获取所有存储资产
        
        Returns:
            Dict[str, Any]: 包含所有存储资产的字典
        """
        logger.info("开始收集腾讯云存储资产")
        
        assets = {
            'cbs_disks': self.get_cbs_disks(),
            'cfs_file_systems': self.get_cfs_file_systems(),
            'cos_buckets': self.get_cos_buckets(),
        }
        
        logger.info("腾讯云存储资产收集完成")
        return assets
    
    def get_cbs_disks(self) -> List[Dict[str, Any]]:
        """
        获取云硬盘列表
        
        Returns:
            List[Dict[str, Any]]: 云硬盘列表
        """
        logger.info("收集云硬盘")
        disks = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            cbs_client = self.session.get_client('cbs', region=region)
            req = cbs_models.DescribeDisksRequest()
            
            resp = cbs_client.DescribeDisks(req)
            
            if resp.DiskSet:
                for disk in resp.DiskSet:
                    disk_info = {
                        'region': region,
                        'disk_id': disk.DiskId,
                        'disk_name': disk.DiskName,
                        'disk_type': disk.DiskType,
                        'disk_usage': disk.DiskUsage,
                        'disk_charge_type': disk.DiskChargeType,
                        'portable': disk.Portable,
                        'placement': {
                            'zone': disk.Placement.Zone,
                            'project_id': disk.Placement.ProjectId,
                        } if disk.Placement else None,
                        'disk_size': disk.DiskSize,
                        'disk_state': disk.DiskState,
                        'instance_id': disk.InstanceId,
                        'create_time': disk.CreateTime,
                        'dead_line_time': disk.DeadlineTime,
                        'rollback_percent': disk.RollbackPercent,
                        'tags': [
                            {
                                'key': tag.Key,
                                'value': tag.Value,
                            } for tag in disk.Tags
                        ] if disk.Tags else [],
                    }
                    disks.append(disk_info)
                    
        except Exception as e:
            logger.error(f"获取云硬盘时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(disks)} 个云硬盘")
        return disks
    
    def get_cfs_file_systems(self) -> List[Dict[str, Any]]:
        """
        获取文件存储列表
        
        Returns:
            List[Dict[str, Any]]: 文件存储列表
        """
        logger.info("收集文件存储")
        file_systems = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            cfs_client = self.session.get_client('cfs', region=region)
            req = cfs_models.DescribeCfsFileSystemsRequest()
            
            resp = cfs_client.DescribeCfsFileSystems(req)
            
            if resp.FileSystems:
                for fs in resp.FileSystems:
                    fs_info = {
                        'region': region,
                        'creation_token': fs.CreationToken,
                        'file_system_id': fs.FileSystemId,
                        'life_cycle_state': fs.LifeCycleState,
                        'creation_time': fs.CreationTime,
                        'size_in_bytes': {
                            'value': fs.SizeInBytes.Value,
                            'timestamp': fs.SizeInBytes.Timestamp,
                        } if fs.SizeInBytes else None,
                        'zone_name': fs.ZoneName,
                        'protocol': fs.Protocol,
                        'storage_type': fs.StorageType,
                        'performance_mode': fs.PerformanceMode,
                        'throughput_mode': fs.ThroughputMode,
                        'tags': [
                            {
                                'key': tag.Key,
                                'value': tag.Value,
                            } for tag in fs.Tags
                        ] if fs.Tags else [],
                    }
                    file_systems.append(fs_info)
                    
        except Exception as e:
            logger.error(f"获取文件存储时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(file_systems)} 个文件存储")
        return file_systems
    
    def get_cos_buckets(self) -> List[Dict[str, Any]]:
        """
        获取对象存储桶列表（区域服务）
        
        Returns:
            List[Dict[str, Any]]: 对象存储桶列表
        """
        logger.info("收集对象存储桶（区域）")
        buckets = []
        
        try:
            # 只收集当前session配置区域的资源
            region = self.session.region
            cos_client = self.session.get_client('cos', region=region)
            
            # 使用COS SDK的方法获取桶列表
            response = cos_client.list_buckets()
            logger.debug(f"COS list_buckets响应: {response}")
            
            # 安全地检查响应结构
            if response and isinstance(response, dict):
                buckets_data = response.get('Buckets')
                if buckets_data and isinstance(buckets_data, dict):
                    bucket_list = buckets_data.get('Bucket', [])
                    if bucket_list and isinstance(bucket_list, list):
                        for bucket in bucket_list:
                            if bucket and isinstance(bucket, dict):
                                # 只收集属于当前区域的存储桶
                                bucket_region = bucket.get('Location', '')
                                if bucket_region == region:
                                    bucket_name = bucket.get('Name', '')
                                    if bucket_name:
                                        bucket_info = {
                                            'region': region,
                                            'bucket_name': bucket_name,
                                            'creation_date': bucket.get('CreationDate', ''),
                                            'location': bucket_region,
                                        }
                                        
                                        # 获取桶的详细配置信息
                                        bucket_info.update(self._get_bucket_details(cos_client, bucket_name))
                                        buckets.append(bucket_info)
                    else:
                        logger.info(f"区域 {region} 中没有COS存储桶数据或数据格式不正确")
                else:
                    logger.info(f"区域 {region} 中没有COS Buckets字段或字段为空")
            else:
                logger.warning(f"区域 {region} 的COS list_buckets返回了空响应或格式不正确")
                        
        except Exception as e:
            logger.error(f"获取对象存储桶时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(buckets)} 个对象存储桶")
        return buckets
    
    def _get_bucket_details(self, cos_client, bucket_name: str) -> Dict[str, Any]:
        """
        获取存储桶的详细配置信息
        
        Args:
            cos_client: COS客户端
            bucket_name: 存储桶名称
            
        Returns:
            Dict[str, Any]: 存储桶详细配置信息
        """
        details = {
            'acl': None,
            'policy': None,
            'cors': None,
            'domain_config': None,
            'encryption': None,
            'versioning': None,
            'lifecycle': None,
            'website': None,
            'logging': None,
            'accelerate': None,
            'referer': None,
            'tagging': None,
            'replication': None,
        }
        
        # 获取ACL配置
        try:
            acl_response = cos_client.get_bucket_acl(Bucket=bucket_name)
            details['acl'] = {
                'owner': acl_response.get('Owner', {}),
                'grants': acl_response.get('Grants', []),
                'public_read': self._check_public_read_acl(acl_response.get('Grants', [])),
                'public_write': self._check_public_write_acl(acl_response.get('Grants', [])),
            }
        except Exception as e:
            logger.debug(f"获取存储桶 {bucket_name} ACL配置失败: {str(e)}")
        
        # 获取存储桶策略
        try:
            policy_response = cos_client.get_bucket_policy(Bucket=bucket_name)
            details['policy'] = {
                'enabled': True,
                'policy': policy_response.get('Policy', ''),
                'policy_json': self._parse_policy_json(policy_response.get('Policy', '')),
            }
        except Exception as e:
            details['policy'] = {'enabled': False, 'policy': '', 'policy_json': None}
            logger.debug(f"获取存储桶 {bucket_name} 策略配置失败: {str(e)}")
        
        # 获取CORS配置
        try:
            cors_response = cos_client.get_bucket_cors(Bucket=bucket_name)
            details['cors'] = {
                'rules': cors_response.get('CORSRules', []),
                'enabled': len(cors_response.get('CORSRules', [])) > 0,
            }
        except Exception as e:
            logger.debug(f"获取存储桶 {bucket_name} CORS配置失败: {str(e)}")
        
        # 获取域名配置
        try:
            domain_response = cos_client.get_bucket_domain(Bucket=bucket_name)
            details['domain_config'] = {
                'rules': domain_response.get('DomainRules', []),
                'custom_domains': self._extract_custom_domains(domain_response.get('DomainRules', [])),
                'cdn_domains': self._extract_cdn_domains(domain_response.get('DomainRules', [])),
            }
        except Exception as e:
            logger.debug(f"获取存储桶 {bucket_name} 域名配置失败: {str(e)}")
        
        # 获取加密配置
        try:
            encryption_response = cos_client.get_bucket_encryption(Bucket=bucket_name)
            details['encryption'] = {
                'rules': encryption_response.get('Rules', []),
                'enabled': len(encryption_response.get('Rules', [])) > 0,
                'default_encryption': self._extract_default_encryption(encryption_response.get('Rules', [])),
            }
        except Exception as e:
            logger.debug(f"获取存储桶 {bucket_name} 加密配置失败: {str(e)}")
        
        # 获取版本控制配置
        try:
            versioning_response = cos_client.get_bucket_versioning(Bucket=bucket_name)
            details['versioning'] = {
                'status': versioning_response.get('Status', 'Disabled'),
                'enabled': versioning_response.get('Status') == 'Enabled',
            }
        except Exception as e:
            logger.debug(f"获取存储桶 {bucket_name} 版本控制配置失败: {str(e)}")
        
        # 获取生命周期配置
        try:
            lifecycle_response = cos_client.get_bucket_lifecycle(Bucket=bucket_name)
            details['lifecycle'] = {
                'rules': lifecycle_response.get('Rules', []),
                'enabled': len(lifecycle_response.get('Rules', [])) > 0,
            }
        except Exception as e:
            logger.debug(f"获取存储桶 {bucket_name} 生命周期配置失败: {str(e)}")
        
        # 获取静态网站配置
        try:
            website_response = cos_client.get_bucket_website(Bucket=bucket_name)
            details['website'] = {
                'enabled': True,
                'index_document': website_response.get('IndexDocument', {}).get('Suffix', ''),
                'error_document': website_response.get('ErrorDocument', {}).get('Key', ''),
                'redirect_all_requests': website_response.get('RedirectAllRequestsTo', {}),
                'routing_rules': website_response.get('RoutingRules', []),
            }
        except Exception as e:
            details['website'] = {'enabled': False}
            logger.debug(f"获取存储桶 {bucket_name} 静态网站配置失败: {str(e)}")
        
        # 获取日志配置
        try:
            logging_response = cos_client.get_bucket_logging(Bucket=bucket_name)
            details['logging'] = {
                'enabled': 'LoggingEnabled' in logging_response,
                'target_bucket': logging_response.get('LoggingEnabled', {}).get('TargetBucket', ''),
                'target_prefix': logging_response.get('LoggingEnabled', {}).get('TargetPrefix', ''),
            }
        except Exception as e:
            details['logging'] = {'enabled': False}
            logger.debug(f"获取存储桶 {bucket_name} 日志配置失败: {str(e)}")
        
        # 获取传输加速配置
        try:
            accelerate_response = cos_client.get_bucket_accelerate(Bucket=bucket_name)
            details['accelerate'] = {
                'status': accelerate_response.get('Status', 'Disabled'),
                'enabled': accelerate_response.get('Status') == 'Enabled',
            }
        except Exception as e:
            details['accelerate'] = {'enabled': False, 'status': 'Disabled'}
            logger.debug(f"获取存储桶 {bucket_name} 传输加速配置失败: {str(e)}")
        
        # 获取防盗链配置
        try:
            referer_response = cos_client.get_bucket_referer(Bucket=bucket_name)
            details['referer'] = {
                'status': referer_response.get('Status', 'Disabled'),
                'enabled': referer_response.get('Status') == 'Enabled',
                'referer_type': referer_response.get('RefererType', ''),
                'domain_list': referer_response.get('DomainList', []),
                'empty_refer_configuration': referer_response.get('EmptyReferConfiguration', ''),
            }
        except Exception as e:
            details['referer'] = {'enabled': False, 'status': 'Disabled'}
            logger.debug(f"获取存储桶 {bucket_name} 防盗链配置失败: {str(e)}")
        
        # 获取标签配置
        try:
            tagging_response = cos_client.get_bucket_tagging(Bucket=bucket_name)
            details['tagging'] = {
                'tags': tagging_response.get('TagSet', {}).get('Tag', []),
                'enabled': len(tagging_response.get('TagSet', {}).get('Tag', [])) > 0,
            }
        except Exception as e:
            details['tagging'] = {'enabled': False, 'tags': []}
            logger.debug(f"获取存储桶 {bucket_name} 标签配置失败: {str(e)}")
        
        # 获取跨地区复制配置
        try:
            replication_response = cos_client.get_bucket_replication(Bucket=bucket_name)
            replication_config = replication_response.get('ReplicationConfiguration', {})
            
            details['replication'] = {
                'enabled': True,
                'role': replication_config.get('Role', ''),
                'rules': replication_config.get('Rules', []),
                'num_rules': len(replication_config.get('Rules', [])),
                'destinations': self._extract_replication_destinations(replication_config.get('Rules', [])),
                'status_summary': self._analyze_replication_status(replication_config.get('Rules', [])),
            }
        except Exception as e:
            details['replication'] = {
                'enabled': False, 
                'role': '', 
                'rules': [], 
                'num_rules': 0,
                'destinations': [],
                'status_summary': {'enabled': 0, 'disabled': 0, 'total': 0},
            }
            logger.debug(f"获取存储桶 {bucket_name} 跨地区复制配置失败: {str(e)}")
        
        # 分析HTTPS强制配置
        details['https_enforced'] = self._check_https_enforced(details)
        
        return details
    
    def _parse_policy_json(self, policy_string: str) -> Dict[str, Any]:
        """解析存储桶策略JSON"""
        try:
            import json
            if policy_string:
                return json.loads(policy_string)
        except Exception as e:
            logger.debug(f"解析存储桶策略JSON失败: {str(e)}")
        return None
    
    def _check_https_enforced(self, bucket_details: Dict[str, Any]) -> Dict[str, Any]:
        """检查是否强制使用HTTPS"""
        https_info = {
            'enforced': False,
            'method': None,  # 'policy' 或 'domain_config'
            'details': {}
        }
        
        # 通过存储桶策略检查HTTPS强制
        policy_info = bucket_details.get('policy', {})
        if policy_info.get('enabled', False) and policy_info.get('policy_json'):
            policy_json = policy_info.get('policy_json', {})
            statements = policy_json.get('Statement', [])
            
            for statement in statements:
                effect = statement.get('Effect', '')
                condition = statement.get('Condition', {})
                
                # 检查是否有强制HTTPS的条件
                if effect == 'Deny' and condition:
                    bool_conditions = condition.get('Bool', {})
                    string_conditions = condition.get('StringEquals', {})
                    
                    # 检查 aws:SecureTransport
                    if bool_conditions.get('aws:SecureTransport') == 'false':
                        https_info['enforced'] = True
                        https_info['method'] = 'policy'
                        https_info['details'] = {
                            'statement': statement,
                            'condition_type': 'aws:SecureTransport'
                        }
                        break
        
        # 通过域名配置检查HTTPS强制
        domain_config = bucket_details.get('domain_config', {})
        if domain_config:
            custom_domains = domain_config.get('custom_domains', [])
            for domain in custom_domains:
                forced_replacement = domain.get('forced_replacement', {})
                if forced_replacement.get('Protocol') == 'https':
                    https_info['enforced'] = True
                    https_info['method'] = 'domain_config'
                    https_info['details'] = {
                        'domain': domain.get('name', ''),
                        'protocol': 'https'
                    }
                    break
        
        return https_info
    
    def _check_public_read_acl(self, grants: List[Dict[str, Any]]) -> bool:
        """检查是否有公开读权限"""
        for grant in grants:
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission', '')
            if (grantee.get('URI') == 'http://cam.qcloud.com/groups/global/AllUsers' and 
                permission in ['READ', 'FULL_CONTROL']):
                return True
        return False
    
    def _check_public_write_acl(self, grants: List[Dict[str, Any]]) -> bool:
        """检查是否有公开写权限"""
        for grant in grants:
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission', '')
            if (grantee.get('URI') == 'http://cam.qcloud.com/groups/global/AllUsers' and 
                permission in ['WRITE', 'WRITE_ACP', 'FULL_CONTROL']):
                return True
        return False
    
    def _extract_custom_domains(self, domain_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """提取自定义域名信息"""
        custom_domains = []
        for rule in domain_rules:
            if rule.get('Type') == 'REST':
                custom_domains.append({
                    'name': rule.get('Name', ''),
                    'status': rule.get('Status', ''),
                    'type': rule.get('Type', ''),
                    'forced_replacement': rule.get('ForcedReplacement', {}),
                })
        return custom_domains
    
    def _extract_cdn_domains(self, domain_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """提取CDN域名信息"""
        cdn_domains = []
        for rule in domain_rules:
            if rule.get('Type') == 'WEBSITE':
                cdn_domains.append({
                    'name': rule.get('Name', ''),
                    'status': rule.get('Status', ''),
                    'type': rule.get('Type', ''),
                })
        return cdn_domains
    
    def _extract_default_encryption(self, encryption_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """提取默认加密配置"""
        if encryption_rules:
            rule = encryption_rules[0]  # 通常只有一个规则
            apply_server_side_encryption = rule.get('ApplyServerSideEncryptionByDefault', {})
            return {
                'sse_algorithm': apply_server_side_encryption.get('SSEAlgorithm', ''),
                'kms_master_key_id': apply_server_side_encryption.get('KMSMasterKeyID', ''),
                'bucket_key_enabled': rule.get('BucketKeyEnabled', False),
            }
        return {}
    
    def _extract_replication_destinations(self, replication_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """提取跨地区复制目标信息"""
        destinations = []
        for rule in replication_rules:
            destination = rule.get('Destination', {})
            if destination:
                bucket_info = destination.get('Bucket', '')
                # 解析 bucket 格式: qcs::cos:<region>::<bucket-name>
                region = ''
                bucket_name = ''
                if bucket_info:
                    parts = bucket_info.split(':')
                    if len(parts) >= 6:
                        region = parts[3] if parts[3] else ''
                        bucket_name = parts[5] if parts[5] else ''
                
                destinations.append({
                    'rule_id': rule.get('ID', ''),
                    'status': rule.get('Status', ''),
                    'prefix': rule.get('Prefix', ''),
                    'destination_bucket': bucket_name,
                    'destination_region': region,
                    'destination_bucket_full': bucket_info,
                    'storage_class': destination.get('StorageClass', ''),
                })
        return destinations
    
    def _analyze_replication_status(self, replication_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析跨地区复制规则状态统计"""
        enabled_count = 0
        disabled_count = 0
        
        for rule in replication_rules:
            status = rule.get('Status', '').lower()
            if status == 'enabled':
                enabled_count += 1
            elif status == 'disabled':
                disabled_count += 1
        
        return {
            'enabled': enabled_count,
            'disabled': disabled_count,
            'total': len(replication_rules),
        } 