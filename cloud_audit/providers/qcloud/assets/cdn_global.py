"""
腾讯云内容分发网络(CDN)全局资产收集器

负责收集腾讯云的CDN全局资源，包括：
- CDN域名管理 - 全局服务（域名管理不区分区域）
- CDN全站加速域名 - 全局服务
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class CDNGlobalAssetCollector:
    """CDN全局资产收集器"""
    
    def __init__(self, session):
        """
        初始化CDN全局资产收集器
        
        Args:
            session: 腾讯云会话对象
        """
        self.session = session
        
    def get_cdn_domains_global(self) -> List[Dict[str, Any]]:
        """
        获取CDN域名列表（全局服务）
        
        注意：CDN域名管理是全局性的，不区分区域
        一次API调用返回账户下所有CDN域名
        
        Returns:
            List[Dict[str, Any]]: CDN域名列表
        """
        logger.info("收集CDN域名（全局）")
        domains = []
        
        try:
            # CDN是全局服务，不需要指定区域
            cdn_client = self.session.get_client('cdn')
            
            # 获取CDN域名列表（全局）
            # 这里需要根据实际的腾讯云CDN API来实现
            # 示例代码，实际需要根据SDK调整
            response = cdn_client.describe_domains()
            
            if hasattr(response, 'Domains') and response.Domains:
                for domain in response.Domains:
                    domain_info = {
                        'domain': domain.get('Domain', ''),
                        'service_type': domain.get('ServiceType', ''),
                        'status': domain.get('Status', ''),
                        'cname': domain.get('Cname', ''),
                        'create_time': domain.get('CreateTime', ''),
                        'type': 'cdn_domain'
                    }
                    domains.append(domain_info)
                    
        except Exception as e:
            logger.error(f"获取CDN域名时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(domains)} 个CDN域名")
        return domains
    
    def get_ecdn_domains_global(self) -> List[Dict[str, Any]]:
        """
        获取ECDN域名列表（全局服务）
        
        Returns:
            List[Dict[str, Any]]: ECDN域名列表
        """
        logger.info("收集ECDN域名（全局）")
        domains = []
        
        try:
            # ECDN也是全局服务
            ecdn_client = self.session.get_client('ecdn')
            
            # 获取ECDN域名列表（全局）
            response = ecdn_client.describe_domains()
            
            if hasattr(response, 'Domains') and response.Domains:
                for domain in response.Domains:
                    domain_info = {
                        'domain': domain.get('Domain', ''),
                        'service_type': domain.get('ServiceType', ''),
                        'status': domain.get('Status', ''),
                        'cname': domain.get('Cname', ''),
                        'create_time': domain.get('CreateTime', ''),
                        'type': 'ecdn_domain'
                    }
                    domains.append(domain_info)
                    
        except Exception as e:
            logger.error(f"获取ECDN域名时发生错误: {str(e)}")
            
        logger.info(f"共收集到 {len(domains)} 个ECDN域名")
        return domains
        
    def get_all_cdn_global_assets(self) -> Dict[str, Dict[str, Any]]:
        """
        获取所有CDN全局资源，按类型分开并返回单个资源项

        Returns:
            Dict[str, Dict[str, Any]]: 按类型分开的CDN全局资源，每个资源项单独存储
        """
        logger.info("开始收集所有CDN全局资源")
        
        # 收集CDN域名
        cdn_domains = {domain.get('domain', f'cdn_domain_{i}'): domain 
                      for i, domain in enumerate(self.get_cdn_domains_global())}
        
        # 收集ECDN域名  
        ecdn_domains = {domain.get('domain', f'ecdn_domain_{i}'): domain 
                       for i, domain in enumerate(self.get_ecdn_domains_global())}
        
        logger.info("CDN全局资源收集完成")
        return {
            'cdn_domains': cdn_domains,
            'ecdn_domains': ecdn_domains
        } 