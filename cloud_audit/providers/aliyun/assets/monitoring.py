"""阿里云监控区域资源处理模块，负责获取与特定区域相关的监控资源信息。

注意：告警规则、告警联系人、联系组、站点监控等是全局资源，请使用 MonitoringGlobalAssetCollector 获取。
"""
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class MonitoringAssetCollector:
    """阿里云监控区域资源收集器"""

    def __init__(self, session):
        """
        初始化监控区域资源收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        # 初始化云监控客户端
        self.cms_client = session.get_client('cms')

    def get_all_monitoring_assets(self) -> Dict[str, Any]:
        """
        获取所有监控区域相关资源
        
        注意：按照"不同区域API返回数据完全一致"的定义，大部分监控资源都是全局的。
        当前版本暂时返回空结构，未来如果发现真正的区域性监控资源会在此添加。
        
        全局监控资源请使用 MonitoringGlobalAssetCollector 获取：
        - 告警规则 (alarm_rules) 
        - 告警联系人 (alarm_contacts)
        - 告警联系组 (alarm_contact_groups)
        - 站点监控 (site_monitors)

        Returns:
            Dict[str, Any]: 监控区域相关资源（当前为空）
        """
        logger.info("获取阿里云监控区域相关资源")
        
        # 当前所有已知的监控资源都是全局的，这里返回空结构
        # 如果未来发现真正的区域性监控资源，会在此处添加
        monitoring_assets = {
            # 预留给未来可能的区域性监控资源
            # 'regional_monitoring_configs': {},  # 假设的区域特定监控配置
        }
        
        logger.info("当前所有监控资源都是全局的，区域收集器返回空结构")
        logger.info("请使用 MonitoringGlobalAssetCollector 获取告警规则、联系人、联系组、站点监控等全局资源")
        return monitoring_assets 