"""
AWS Session Implementation with Role Switching Support
"""
from typing import Any, Dict, Optional, Tuple, List
import boto3
from botocore.exceptions import ClientError
from ...base import CloudSession


class AWSSession(CloudSession):
    """
    AWS session implementation with support for role switching and temporary credentials
    """

    """AWS session implementation"""

    def __init__(self, session: boto3.Session):
        self._session = session

    def get_client(self, service_name: str) -> Any:
        """Get a boto3 client for the specified service"""
        return self._session.client(service_name)

    def get_account_id(self) -> str:
        """Get the current AWS account ID"""
        sts = self.get_client('sts')
        return sts.get_caller_identity()["Account"]

    def get_available_regions(self, service_name: str = 'ec2') -> List[str]:
        """
        获取AWS所有可用区域
        
        Args:
            service_name: 服务名称，默认为ec2（所有区域都支持ec2服务）
            
        Returns:
            List[str]: 区域代码列表，如 ['us-east-1', 'us-west-1', ...]
        """
        try:
            # 使用EC2服务来获取所有可用区域
            ec2 = self.get_client('ec2')
            response = ec2.describe_regions()
            return [region['RegionName'] for region in response['Regions']]
        except Exception as e:
            # # 如果出错，返回常见区域列表
            # common_regions = [
            #     'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            #     'ca-central-1',
            #     'eu-west-1', 'eu-west-2', 'eu-west-3',
            #     'eu-central-1', 'eu-north-1', 'eu-south-1',
            #     'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
            #     'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3',
            #     'ap-south-1',
            #     'sa-east-1',
            #     'af-south-1',
            #     'me-south-1'
            # ]
            # return common_regions
            raise e

    def get_enabled_regions(self) -> List[str]:
        """
        获取当前账号启用的所有区域
        
        Returns:
            List[str]: 启用的区域代码列表
        """
        try:
            # 使用账号管理服务获取启用的区域
            account = self.get_client('account')
            response = account.list_regions()
            return [region['RegionName'] for region in response['Regions'] if region['RegionOptStatus'] == 'ENABLED']
        except Exception:
            # 如果出错或服务不可用，回退到获取所有可用区域
            return self.get_available_regions()

    @property
    def boto3_session(self) -> boto3.Session:
        """Get the underlying boto3 session"""
        return self._session

    def assume_role(
        self,
        role_arn: str,
        session_name: str = "CloudAuditSession",
        external_id: Optional[str] = None,
        duration_seconds: int = 3600,
    ) -> "AWSSession":
        """
        Assume an IAM role and return a new session with the temporary credentials.

        Args:
            role_arn: The ARN of the role to assume
            session_name: Name for the role session
            external_id: External ID for additional security (if required)
            duration_seconds: Duration of the session in seconds (default: 1 hour)

        Returns:
            A new AWSSession instance with the assumed role credentials
        """
        sts_client = self.get_client("sts")
        assume_role_kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": duration_seconds,
        }

        if external_id:
            assume_role_kwargs["ExternalId"] = external_id

        try:
            response = sts_client.assume_role(**assume_role_kwargs)
            credentials = response["Credentials"]
            
            # 保留原始会话的区域设置
            region = self._session.region_name
            
            # Create a new session with the temporary credentials
            new_session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=region,  # 保留原始会话的区域
            )
            
            return AWSSession(new_session)
        except ClientError as e:
            raise Exception(f"Failed to assume role: {str(e)}")

    def get_temporary_credentials(
        self,
        role_arn: str,
        session_name: str = "CloudAuditSession",
        external_id: Optional[str] = None,
        duration_seconds: int = 3600,
    ) -> Dict[str, str]:
        """
        Get temporary credentials for an assumed role.

        Args:
            role_arn: The ARN of the role to assume
            session_name: Name for the role session
            external_id: External ID for additional security (if required)
            duration_seconds: Duration of the session in seconds (default: 1 hour)

        Returns:
            Dictionary containing temporary credentials (access key, secret key, session token)
        """
        sts_client = self.get_client("sts")
        assume_role_kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": duration_seconds,
        }

        if external_id:
            assume_role_kwargs["ExternalId"] = external_id

        try:
            response = sts_client.assume_role(**assume_role_kwargs)
            credentials = response["Credentials"]
            
            return {
                "AccessKeyId": credentials["AccessKeyId"],
                "SecretAccessKey": credentials["SecretAccessKey"],
                "SessionToken": credentials["SessionToken"],
                "Expiration": credentials["Expiration"].isoformat(),
            }
        except ClientError as e:
            raise Exception(f"Failed to get temporary credentials: {str(e)}")

    @classmethod
    def create_from_credentials(
        cls,
        access_key: str,
        secret_key: str,
        session_token: Optional[str] = None,
        region: Optional[str] = None,
    ) -> "AWSSession":
        """
        Create a new AWS session from credentials.

        Args:
            access_key: AWS access key ID
            secret_key: AWS secret access key
            session_token: AWS session token (optional)
            region: AWS region (optional)

        Returns:
            A new AWSSession instance
        """
        session_kwargs = {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
        }
        
        if session_token:
            session_kwargs["aws_session_token"] = session_token
        if region:
            session_kwargs["region_name"] = region

        session = boto3.Session(**session_kwargs)
        return cls(session)
