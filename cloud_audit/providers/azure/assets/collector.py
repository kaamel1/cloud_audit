"""Azure资产收集器主入口模块"""
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def collect_azure_assets_and_flows(session, output_dir: str) -> Dict[str, Any]:
    """
    收集Azure所有资产和流量信息
    
    Args:
        session: Azure会话对象
        output_dir: 输出目录
        
    Returns:
        Dict[str, Any]: 所有资产信息
    """
    logger.info("开始收集Azure资产信息")
    
    all_assets = {
        'subscription_info': {},
        'compute': {},
        'network': {},
        'storage': {},
        'database': {},
        'security': {},
        'iam': {},
        'monitoring': {},
        'web': {},
        'keyvault': {}
    }
    
    try:
        # 获取订阅信息
        all_assets['subscription_info'] = session.get_subscription_info()
        logger.info("已收集订阅信息")
        
        # 收集计算资源
        from .compute import ComputeAssetCollector
        compute_collector = ComputeAssetCollector(session)
        all_assets['compute'] = compute_collector.get_all_compute_assets()
        logger.info("已收集计算资源")
        
        # 收集网络资源
        from .network import NetworkAssetCollector
        network_collector = NetworkAssetCollector(session)
        all_assets['network'] = network_collector.get_all_network_assets()
        logger.info("已收集网络资源")
        
        # 收集存储资源
        from .storage import StorageAssetCollector
        storage_collector = StorageAssetCollector(session)
        all_assets['storage'] = storage_collector.get_all_storage_assets()
        logger.info("已收集存储资源")
        
        # 收集数据库资源
        from .database import DatabaseAssetCollector
        database_collector = DatabaseAssetCollector(session)
        all_assets['database'] = database_collector.get_all_database_assets()
        logger.info("已收集数据库资源")
        
        # 收集安全资源
        from .security import SecurityAssetCollector
        security_collector = SecurityAssetCollector(session)
        all_assets['security'] = security_collector.get_all_security_assets()
        logger.info("已收集安全资源")
        
        # 收集IAM资源
        from .iam import IAMAssetCollector
        iam_collector = IAMAssetCollector(session)
        all_assets['iam'] = iam_collector.get_all_iam_assets()
        logger.info("已收集IAM资源")
        
        # 收集监控资源
        from .monitoring import MonitoringAssetCollector
        monitoring_collector = MonitoringAssetCollector(session)
        all_assets['monitoring'] = monitoring_collector.get_all_monitoring_assets()
        logger.info("已收集监控资源")
        
        # 收集Web应用资源
        from .web import WebAssetCollector
        web_collector = WebAssetCollector(session)
        all_assets['web'] = web_collector.get_all_web_assets()
        logger.info("已收集Web应用资源")
        
        # 收集Key Vault资源
        from .keyvault import KeyVaultAssetCollector
        keyvault_collector = KeyVaultAssetCollector(session)
        all_assets['keyvault'] = keyvault_collector.get_all_keyvault_assets()
        logger.info("已收集Key Vault资源")
        
    except Exception as e:
        logger.error(f"收集Azure资产时发生错误: {str(e)}")
        raise
    
    logger.info("Azure资产收集完成")
    return {
        'type': 'azure',
        'assets': all_assets,
    } 