"""Azure资产审计模块，负责整合资产收集和分析功能"""
import os
import json
import logging
from typing import Dict, Any

from ...base import CloudAuditor
from .assets.compute import ComputeAssetCollector
from .assets.network import NetworkAssetCollector
from .assets.storage import StorageAssetCollector

logger = logging.getLogger(__name__)

class DateTimeEncoder(json.JSONEncoder):
    """处理日期时间的JSON编码器"""
    def default(self, obj):
        import datetime
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        return super().default(obj)

class AzureAuditor(CloudAuditor):
    """Azure资产审计器"""
    
    def __init__(self, session, output_dir: str = "output"):
        """
        初始化Azure审计器
        
        Args:
            session: Azure会话对象
            output_dir: 输出目录路径
        """
        super().__init__(session, output_dir)
        
        # 初始化各个收集器和分析器
        self.compute_collector = ComputeAssetCollector(session)
        self.storage_collector = StorageAssetCollector(session)
        self.network_collector = NetworkAssetCollector(session)
            
    def get_compute_assets(self) -> Dict[str, Any]:
        """
        获取计算资源资产
        
        Returns:
            Dict[str, Any]: 计算资源资产信息
        """
        logger.info("获取计算资源资产")
        return self.compute_collector.get_all_compute_assets()
    
    def get_storage_assets(self) -> Dict[str, Any]:
        """
        获取存储资源资产
        
        Returns:
            Dict[str, Any]: 存储资源资产信息
        """
        logger.info("获取存储资源资产")
        return self.storage_collector.get_all_storage_assets()
    
    def get_network_assets(self) -> Dict[str, Any]:
        """
        获取网络资源资产
        
        Returns:
            Dict[str, Any]: 网络资源资产信息
        """
        logger.info("获取网络资源资产")
        return self.network_collector.get_all_network_assets()
    
    def get_all_assets(self) -> Dict[str, Any]:
        """
        获取所有资产信息，并按资源类型分类保存

        Returns:
            Dict[str, Any]: 所有资产信息
        """
        # from .assets.collector import collect_azure_assets_and_flows
        # return collect_azure_assets_and_flows(self.session, self.output_dir)
        return {}
    
    def get_all_assets_global(self) -> Dict[str, Any]:
        """
        获取所有全局资产信息，并按资源类型分类保存
        """
        from .assets.collector import collect_azure_assets_and_flows
        return collect_azure_assets_and_flows(self.session, self.output_dir)
     
    def save_json(self, data: Dict[str, Any], relative_path: str, filename: str):
        """
        保存JSON数据到指定路径
        
        Args:
            data: 要保存的数据
            relative_path: 相对输出目录的路径
            filename: 文件名（不含扩展名）
        """
        # 确保目录存在
        full_path = os.path.join(self.output_dir, relative_path)
        os.makedirs(full_path, exist_ok=True)
        
        # 保存文件
        with open(os.path.join(full_path, f'{filename}.json'), 'w') as f:
            json.dump(data, f, indent=2, cls=DateTimeEncoder) 