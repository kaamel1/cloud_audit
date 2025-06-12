"""
腾讯云全局资产收集器

负责收集腾讯云的全局资源，包括：
- CAM用户管理 - 全局服务
- CAM组管理 - 全局服务  
- CAM角色管理 - 全局服务
- CAM策略管理 - 全局服务
- COS对象存储 - 全局服务（一次API调用返回全部区域存储桶）
- CDN内容分发网络 - 全局服务（域名管理不区分区域）
"""

import logging
from typing import Dict, Any, List
from .cam_global import CAMGlobalAssetCollector
from .cos_global import COSGlobalAssetCollector
from .cdn_global import CDNGlobalAssetCollector

logger = logging.getLogger(__name__)

class QCloudGlobalAssetCollector:
    """腾讯云全局资产收集器"""
    
    def __init__(self, session):
        """
        初始化腾讯云全局资产收集器

        Args:
            session: 腾讯云会话对象
        """
        self.session = session
        # 全局服务collectors
        self.cam_collector = CAMGlobalAssetCollector(session)
        self.cos_collector = COSGlobalAssetCollector(session)
        self.cdn_collector = CDNGlobalAssetCollector(session)

    def collect_all_global_assets(self) -> Dict[str, Any]:
        """
        收集所有腾讯云全局资产
        
        Returns:
            Dict[str, Any]: 所有腾讯云全局资产
        """
        logger.info("开始收集所有腾讯云全局资产...")
        
        assets = {
            'cam': self.cam_collector.get_all_cam_global_assets(),
            'cos': self.cos_collector.get_all_cos_global_assets(),
            'cdn': self.cdn_collector.get_all_cdn_global_assets(),
        }
        
        logger.info("所有腾讯云全局资产收集完成")
        return assets

    def collect_assets_and_generate_flows(self, output_dir=None) -> Dict[str, Any]:
        """
        收集所有全局资产并生成数据流路径

        Args:
            output_dir: 输出目录

        Returns:
            Dict[str, Any]: 包含全局资产和数据流路径的字典
        """
        assets = self.collect_all_global_assets()
        
        return {
            'type': 'qcloud_global',
            'assets': assets,
        }


def collect_qcloud_global_assets_and_flows(session, output_dir=None) -> Dict[str, Any]:
    """
    收集腾讯云全局资产和生成数据流路径的便捷函数

    Args:
        session: 腾讯云会话对象
        output_dir: 输出目录

    Returns:
        Dict[str, Any]: 包含全局资产和数据流路径的字典
    """
    collector = QCloudGlobalAssetCollector(session)
    return collector.collect_assets_and_generate_flows(output_dir) 