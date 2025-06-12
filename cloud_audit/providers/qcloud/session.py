"""
QCloud Session Implementation with Role Switching Support
"""
from typing import Any, Dict, Optional, List
from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.sts.v20180813 import sts_client, models as sts_models
from tencentcloud.cvm.v20170312 import cvm_client
from ...base import CloudSession


class QCloudSession(CloudSession):
    """
    腾讯云会话实现，支持角色切换和临时凭证
    """

    def __init__(self, credential_obj: credential.Credential, region: str = "ap-beijing"):
        """
        初始化腾讯云会话
        
        Args:
            credential_obj: 腾讯云凭证对象
            region: 地域
        """
        self._credential = credential_obj
        self._region = region

    def get_client(self, service_name: str, version: str = None, region: str = None) -> Any:
        """
        获取指定服务的客户端
        
        Args:
            service_name: 服务名称 (如 'cvm', 'vpc', 'cos' 等)
            version: API版本 (如 'v20170312')
            region: 地域 (可选，默认使用会话地域)
        
        Returns:
            腾讯云服务客户端
        """
        client_region = region or self._region
        
        # 腾讯云服务客户端映射
        service_clients = {
            'cvm': ('tencentcloud.cvm.v20170312.cvm_client', 'CvmClient'),
            'vpc': ('tencentcloud.vpc.v20170312.vpc_client', 'VpcClient'),
            'clb': ('tencentcloud.clb.v20180317.clb_client', 'ClbClient'),
            'cbs': ('tencentcloud.cbs.v20170312.cbs_client', 'CbsClient'),
            'cfs': ('tencentcloud.cfs.v20190719.cfs_client', 'CfsClient'),
            'cdn': ('tencentcloud.cdn.v20180606.cdn_client', 'CdnClient'),
            'cdb': ('tencentcloud.cdb.v20170320.cdb_client', 'CdbClient'),
            'redis': ('tencentcloud.redis.v20180412.redis_client', 'RedisClient'),
            'mongodb': ('tencentcloud.mongodb.v20190725.mongodb_client', 'MongodbClient'),
            'sqlserver': ('tencentcloud.sqlserver.v20180328.sqlserver_client', 'SqlserverClient'),
            'postgres': ('tencentcloud.postgres.v20170312.postgres_client', 'PostgresClient'),
            'sts': ('tencentcloud.sts.v20180813.sts_client', 'StsClient'),
            'cam': ('tencentcloud.cam.v20190116.cam_client', 'CamClient'),
            'ssl': ('tencentcloud.ssl.v20191205.ssl_client', 'SslClient'),
            'domain': ('tencentcloud.domain.v20180808.domain_client', 'DomainClient'),
            'dnspod': ('tencentcloud.dnspod.v20210323.dnspod_client', 'DnspodClient'),
            'tag': ('tencentcloud.tag.v20180813.tag_client', 'TagClient'),
            'monitor': ('tencentcloud.monitor.v20180724.monitor_client', 'MonitorClient'),
            'cls': ('tencentcloud.cls.v20201016.cls_client', 'ClsClient'),
            'lighthouse': ('tencentcloud.lighthouse.v20200324.lighthouse_client', 'LighthouseClient'),
            'tcr': ('tencentcloud.tcr.v20190924.tcr_client', 'TcrClient'),
            'tke': ('tencentcloud.tke.v20180525.tke_client', 'TkeClient'),
            'scf': ('tencentcloud.scf.v20180416.scf_client', 'ScfClient'),
            'apigateway': ('tencentcloud.apigateway.v20180808.apigateway_client', 'ApigatewayClient'),
        }
        
        # COS对象存储使用不同的SDK，需要特殊处理
        if service_name == 'cos':
            try:
                from qcloud_cos import CosConfig, CosS3Client
                # COS使用不同的配置方式
                config = CosConfig(
                    Region=client_region, 
                    SecretId=self._credential.secretId, 
                    SecretKey=self._credential.secretKey,
                    Token=self._credential.token
                )
                return CosS3Client(config)
            except ImportError as e:
                raise ValueError(f"Failed to import COS client: {str(e)}. Please install cos-python-sdk-v5")
        
        if service_name not in service_clients:
            raise ValueError(f"Unsupported service: {service_name}")
        
        module_path, class_name = service_clients[service_name]
        
        # 动态导入并创建客户端
        try:
            module = __import__(module_path, fromlist=[class_name])
            client_class = getattr(module, class_name)
            return client_class(self._credential, client_region)
        except ImportError as e:
            raise ValueError(f"Failed to import {service_name} client: {str(e)}")
    
    def get_account_id(self) -> str:
        """获取当前腾讯云账户ID"""
        try:
            sts = self.get_client('sts')
            req = sts_models.GetCallerIdentityRequest()
            resp = sts.GetCallerIdentity(req)
            return resp.AccountId
        except TencentCloudSDKException as e:
            raise Exception(f"Failed to get account ID: {str(e)}")

    def get_enabled_regions(self) -> List[str]:
        """
        获取当前账号可用的所有地域
        
        Returns:
            List[str]: 可用地域代码列表
        """
        try:
            cvm = self.get_client('cvm')
            req = cvm_client.models.DescribeRegionsRequest()
            resp = cvm.DescribeRegions(req)
            return [region.Region for region in resp.RegionSet]
        except TencentCloudSDKException as e:
            # 如果出错，返回常见地域列表
            common_regions = [
                'ap-beijing', 'ap-chengdu', 'ap-chongqing', 'ap-guangzhou',
                'ap-shanghai', 'ap-nanjing', 'ap-hongkong', 'ap-singapore',
                'ap-tokyo', 'ap-seoul', 'ap-mumbai', 'ap-bangkok',
                'na-ashburn', 'na-siliconvalley', 'na-toronto',
                'eu-frankfurt', 'eu-moscow'
            ]
            return common_regions

    def get_available_zones(self, region: str = None) -> List[str]:
        """
        获取指定地域的可用区列表
        
        Args:
            region: 地域代码，默认使用当前会话地域
            
        Returns:
            List[str]: 可用区代码列表
        """
        try:
            target_region = region or self._region
            cvm = self.get_client('cvm', region=target_region)
            req = cvm_client.models.DescribeZonesRequest()
            resp = cvm.DescribeZones(req)
            return [zone.Zone for zone in resp.ZoneSet]
        except TencentCloudSDKException as e:
            raise Exception(f"Failed to get available zones: {str(e)}")

    @property
    def credential(self) -> credential.Credential:
        """获取底层腾讯云凭证对象"""
        return self._credential
    
    @property
    def region(self) -> str:
        """获取当前地域"""
        return self._region

    def assume_role(
        self,
        role_arn: str,
        session_name: str = "CloudAuditSession",
        duration_seconds: int = 3600,
        policy: Optional[str] = None,
    ) -> "QCloudSession":
        """
        切换到指定角色并返回新的会话
        
        Args:
            role_arn: 角色ARN
            session_name: 会话名称
            duration_seconds: 会话持续时间(秒)
            policy: 会话策略(JSON格式字符串)
        
        Returns:
            新的QCloudSession实例
        """
        try:
            sts = self.get_client('sts')
            req = sts_models.AssumeRoleRequest()
            req.RoleArn = role_arn
            req.RoleSessionName = session_name
            req.DurationSeconds = duration_seconds
            
            if policy:
                req.Policy = policy
            
            resp = sts.AssumeRole(req)
            
            # 创建新的凭证对象
            new_credential = credential.Credential(
                resp.Credentials.TmpSecretId,
                resp.Credentials.TmpSecretKey,
                resp.Credentials.Token
            )
            
            return QCloudSession(new_credential, self._region)
            
        except TencentCloudSDKException as e:
            raise Exception(f"Failed to assume role: {str(e)}")

    def get_temporary_credentials(
        self,
        role_arn: str,
        session_name: str = "CloudAuditSession",
        duration_seconds: int = 3600,
        policy: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        获取临时凭证
        
        Args:
            role_arn: 角色ARN
            session_name: 会话名称
            duration_seconds: 会话持续时间(秒)
            policy: 会话策略(JSON格式字符串)
        
        Returns:
            包含临时凭证的字典
        """
        try:
            sts = self.get_client('sts')
            req = sts_models.AssumeRoleRequest()
            req.RoleArn = role_arn
            req.RoleSessionName = session_name
            req.DurationSeconds = duration_seconds
            
            if policy:
                req.Policy = policy
            
            resp = sts.AssumeRole(req)
            
            return {
                "TmpSecretId": resp.Credentials.TmpSecretId,
                "TmpSecretKey": resp.Credentials.TmpSecretKey,
                "Token": resp.Credentials.Token,
                "ExpiredTime": str(resp.Credentials.ExpiredTime),
            }
            
        except TencentCloudSDKException as e:
            raise Exception(f"Failed to get temporary credentials: {str(e)}")

    @classmethod
    def create_from_credentials(
        cls,
        secret_id: str,
        secret_key: str,
        token: Optional[str] = None,
        region: Optional[str] = None,
    ) -> "QCloudSession":
        """
        从凭证创建新的腾讯云会话
        
        Args:
            secret_id: SecretId
            secret_key: SecretKey
            token: 临时访问凭证Token (可选)
            region: 地域 (可选)
        
        Returns:
            新的QCloudSession实例
        """
        if token:
            cred = credential.Credential(secret_id, secret_key, token)
        else:
            cred = credential.Credential(secret_id, secret_key)
            
        return cls(cred, region or "ap-beijing") 