"""
AWS ACM Global资源处理模块，负责获取us-east-1区域的SSL/TLS证书信息。
这些证书可以被CloudFront等全球服务使用。
"""
import boto3
import logging
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class ACMGlobalAssetCollector:
    """AWS ACM Global资源收集器（us-east-1区域）"""

    def __init__(self, session):
        """
        初始化ACM Global资源收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        # ACM Global必须使用us-east-1区域，因为CloudFront需要
        self.acm_client = session.get_client('acm')

    def get_certificates(self) -> List[Dict[str, Any]]:
        """
        获取ACM证书信息

        Returns:
            List[Dict[str, Any]]: 证书列表
        """
        logger.info("获取ACM Global证书信息（us-east-1区域）")
        certificates = []

        try:
            # 获取所有证书状态的证书
            certificate_statuses = ['PENDING_VALIDATION', 'ISSUED', 'INACTIVE', 'EXPIRED', 'VALIDATION_TIMED_OUT', 'REVOKED', 'FAILED']
            
            for status in certificate_statuses:
                try:
                    paginator = self.acm_client.get_paginator('list_certificates')
                    
                    for page in paginator.paginate(CertificateStatuses=[status]):
                        for cert in page.get('CertificateSummaryList', []):
                            # 获取证书详细信息
                            cert_detail = self.acm_client.describe_certificate(
                                CertificateArn=cert['CertificateArn']
                            )
                            
                            certificate_info = cert_detail['Certificate']
                            
                            # 获取证书标签
                            tags = []
                            try:
                                tags_response = self.acm_client.list_tags_for_certificate(
                                    CertificateArn=cert['CertificateArn']
                                )
                                tags = tags_response.get('Tags', [])
                            except Exception as e:
                                logger.warning(f"获取证书 {cert['CertificateArn']} 标签失败: {str(e)}")

                            # 获取证书验证选项
                            domain_validation_options = certificate_info.get('DomainValidationOptions', [])
                            
                            # 获取证书扩展验证
                            extended_key_usages = certificate_info.get('ExtendedKeyUsages', [])
                            key_usages = certificate_info.get('KeyUsages', [])
                            
                            # 获取证书选项
                            options = certificate_info.get('Options', {})
                            
                            # 获取证书关联的资源
                            in_use_by = certificate_info.get('InUseBy', [])
                            
                            cert_info = {
                                'CertificateArn': certificate_info.get('CertificateArn'),
                                'DomainName': certificate_info.get('DomainName'),
                                'SubjectAlternativeNames': certificate_info.get('SubjectAlternativeNames', []),
                                'DomainValidationOptions': domain_validation_options,
                                'Serial': certificate_info.get('Serial'),
                                'Subject': certificate_info.get('Subject'),
                                'Issuer': certificate_info.get('Issuer'),
                                'CreatedAt': certificate_info.get('CreatedAt'),
                                'IssuedAt': certificate_info.get('IssuedAt'),
                                'ImportedAt': certificate_info.get('ImportedAt'),
                                'Status': certificate_info.get('Status'),
                                'RevokedAt': certificate_info.get('RevokedAt'),
                                'RevocationReason': certificate_info.get('RevocationReason'),
                                'NotBefore': certificate_info.get('NotBefore'),
                                'NotAfter': certificate_info.get('NotAfter'),
                                'KeyAlgorithm': certificate_info.get('KeyAlgorithm'),
                                'SignatureAlgorithm': certificate_info.get('SignatureAlgorithm'),
                                'InUseBy': in_use_by,
                                'FailureReason': certificate_info.get('FailureReason'),
                                'Type': certificate_info.get('Type'),
                                'KeyUsages': key_usages,
                                'ExtendedKeyUsages': extended_key_usages,
                                'CertificateTransparencyLoggingPreference': certificate_info.get('CertificateTransparencyLoggingPreference'),
                                'RenewalEligibility': certificate_info.get('RenewalEligibility'),
                                'RenewalSummary': certificate_info.get('RenewalSummary'),
                                'Options': options,
                                'Tags': tags,
                                'Region': 'us-east-1'  # 明确标识这是全球区域的证书
                            }
                            
                            # 添加证书到期状态分析
                            if certificate_info.get('NotAfter'):
                                not_after = certificate_info['NotAfter']
                                if isinstance(not_after, datetime):
                                    days_until_expiry = (not_after - datetime.now(not_after.tzinfo)).days
                                    cert_info['DaysUntilExpiry'] = days_until_expiry
                                    cert_info['ExpiryStatus'] = self._get_expiry_status(days_until_expiry)
                            
                            certificates.append(cert_info)
                            
                except Exception as e:
                    logger.warning(f"获取状态 {status} 的证书失败: {str(e)}")

        except Exception as e:
            logger.error(f"获取ACM Global证书信息失败: {str(e)}")

        return certificates

    def _get_expiry_status(self, days_until_expiry: int) -> str:
        """
        获取证书到期状态
        
        Args:
            days_until_expiry: 距离到期的天数
            
        Returns:
            str: 到期状态
        """
        if days_until_expiry < 0:
            return 'EXPIRED'
        elif days_until_expiry <= 7:
            return 'EXPIRING_SOON'
        elif days_until_expiry <= 30:
            return 'EXPIRING_THIS_MONTH'
        elif days_until_expiry <= 90:
            return 'EXPIRING_IN_90_DAYS'
        else:
            return 'VALID'

    def get_certificate_authorities(self) -> List[Dict[str, Any]]:
        """
        获取私有证书颁发机构信息

        Returns:
            List[Dict[str, Any]]: 私有CA列表
        """
        logger.info("获取ACM PCA私有证书颁发机构信息（us-east-1区域）")
        certificate_authorities = []

        try:
            # 创建ACM PCA客户端
            acm_pca_client = self.session.get_client('acm-pca', region_name='us-east-1')
            
            paginator = acm_pca_client.get_paginator('list_certificate_authorities')
            
            for page in paginator.paginate():
                for ca in page.get('CertificateAuthorities', []):
                    ca_arn = ca.get('Arn')
                    
                    # 获取CA详细信息
                    try:
                        ca_detail = acm_pca_client.describe_certificate_authority(
                            CertificateAuthorityArn=ca_arn
                        )
                        
                        ca_info = ca_detail['CertificateAuthority']
                        
                        # 获取CA标签
                        tags = []
                        try:
                            tags_response = acm_pca_client.list_tags_for_certificate_authority(
                                CertificateAuthorityArn=ca_arn
                            )
                            tags = tags_response.get('Tags', [])
                        except Exception as e:
                            logger.warning(f"获取CA {ca_arn} 标签失败: {str(e)}")
                        
                        # 获取CA策略
                        policy = None
                        try:
                            policy_response = acm_pca_client.get_policy(
                                ResourceArn=ca_arn
                            )
                            policy = policy_response.get('Policy')
                        except Exception as e:
                            logger.debug(f"CA {ca_arn} 没有策略或获取策略失败: {str(e)}")
                        
                        ca_certificate_authority_info = {
                            'Arn': ca_info.get('Arn'),
                            'OwnerAccount': ca_info.get('OwnerAccount'),
                            'CreatedAt': ca_info.get('CreatedAt'),
                            'LastStateChangeAt': ca_info.get('LastStateChangeAt'),
                            'Type': ca_info.get('Type'),
                            'Serial': ca_info.get('Serial'),
                            'Status': ca_info.get('Status'),
                            'NotBefore': ca_info.get('NotBefore'),
                            'NotAfter': ca_info.get('NotAfter'),
                            'FailureReason': ca_info.get('FailureReason'),
                            'CertificateAuthorityConfiguration': ca_info.get('CertificateAuthorityConfiguration'),
                            'RevocationConfiguration': ca_info.get('RevocationConfiguration'),
                            'RestorableUntil': ca_info.get('RestorableUntil'),
                            'KeyStorageSecurityStandard': ca_info.get('KeyStorageSecurityStandard'),
                            'UsageMode': ca_info.get('UsageMode'),
                            'Tags': tags,
                            'Policy': policy,
                            'Region': 'us-east-1'
                        }
                        
                        certificate_authorities.append(ca_certificate_authority_info)
                        
                    except Exception as e:
                        logger.warning(f"获取CA {ca_arn} 详细信息失败: {str(e)}")

        except Exception as e:
            logger.error(f"获取ACM PCA信息失败: {str(e)}")

        return certificate_authorities

    def get_all_acm_global_assets(self) -> Dict[str, Any]:
        """
        获取所有ACM Global资源

        Returns:
            Dict[str, Any]: 所有ACM Global资源
        """
        logger.info("获取所有ACM Global资源")
        
        certificates = self.get_certificates()
        certificate_authorities = self.get_certificate_authorities()
        
        # 按状态分组证书，便于分析
        certificates_by_status = {}
        for cert in certificates:
            status = cert.get('Status', 'UNKNOWN')
            if status not in certificates_by_status:
                certificates_by_status[status] = []
            certificates_by_status[status].append(cert)
        
        # 按到期状态分组证书
        certificates_by_expiry = {}
        for cert in certificates:
            expiry_status = cert.get('ExpiryStatus', 'UNKNOWN')
            if expiry_status not in certificates_by_expiry:
                certificates_by_expiry[expiry_status] = []
            certificates_by_expiry[expiry_status].append(cert)
        
        acm_global_assets = {
            'certificates': {cert['CertificateArn']: cert for cert in certificates},
            'certificate_authorities': {ca['Arn']: ca for ca in certificate_authorities},
            'certificates_by_status': certificates_by_status,
            'certificates_by_expiry': certificates_by_expiry,
            'summary': {
                'total_certificates': len(certificates),
                'total_certificate_authorities': len(certificate_authorities),
                'region': 'us-east-1'
            }
        }
        
        logger.info(f"已获取 {len(certificates)} 个ACM证书, {len(certificate_authorities)} 个私有CA（us-east-1区域）")
        return acm_global_assets 