"""
腾讯云资产收集模块

本模块包含各种腾讯云资产的收集器，用于获取计算、存储、网络等各类资源信息。
"""

from .compute import ComputeAssetCollector
from .storage import StorageAssetCollector  
from .network import NetworkAssetCollector
from .database import DatabaseAssetCollector
from .security import SecurityAssetCollector
from .cdn import CDNAssetCollector
from .monitor import MonitorAssetCollector

__all__ = [
    'ComputeAssetCollector',
    'StorageAssetCollector',
    'NetworkAssetCollector', 
    'DatabaseAssetCollector',
    'SecurityAssetCollector',
    'CDNAssetCollector',
    'MonitorAssetCollector',
] 