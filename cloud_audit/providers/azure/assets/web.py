"""Azure Web应用资源收集器"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class WebAssetCollector:
    """Azure Web应用资源收集器"""
    
    def __init__(self, session):
        """
        初始化Web应用资源收集器
        
        Args:
            session: Azure会话对象
        """
        self.session = session
        try:
            self.web_client = session.get_client('web')
        except Exception as e:
            logger.warning(f"无法初始化Web客户端: {str(e)}")
            self.web_client = None
    
    def get_app_service_plans(self) -> Dict[str, Any]:
        """
        获取应用服务计划列表
        
        Returns:
            Dict[str, Any]: 应用服务计划信息字典，键为应用服务计划ID
        """
        if not self.web_client:
            logger.warning("Web客户端未初始化，跳过应用服务计划收集")
            return {}
            
        try:
            app_service_plans = {}
            for plan in self.web_client.app_service_plans.list():
                plan_dict = {
                    'id': plan.id,
                    'name': plan.name,
                    'location': plan.location,
                    'resource_group': plan.id.split('/')[4] if plan.id else None,
                    'kind': plan.kind,
                    'sku': {
                        'name': plan.sku.name,
                        'tier': plan.sku.tier,
                        'size': plan.sku.size,
                        'family': plan.sku.family,
                        'capacity': plan.sku.capacity
                    } if plan.sku else None,
                    'status': plan.status,
                    'provisioning_state': plan.provisioning_state,
                    'maximum_number_of_workers': plan.maximum_number_of_workers,
                    'tags': dict(plan.tags) if plan.tags else {}
                }
                app_service_plans[plan.id] = plan_dict
            
            logger.info(f"获取到 {len(app_service_plans)} 个应用服务计划")
            return app_service_plans
            
        except Exception as e:
            logger.error(f"获取应用服务计划失败: {str(e)}")
            return {}
    
    def get_web_apps(self) -> Dict[str, Any]:
        """
        获取Web应用列表
        
        Returns:
            Dict[str, Any]: Web应用信息字典，键为Web应用ID
        """
        if not self.web_client:
            logger.warning("Web客户端未初始化，跳过Web应用收集")
            return {}
            
        try:
            web_apps = {}
            for app in self.web_client.web_apps.list():
                app_dict = {
                    'id': app.id,
                    'name': app.name,
                    'location': app.location,
                    'resource_group': app.id.split('/')[4] if app.id else None,
                    'kind': app.kind,
                    'state': app.state,
                    'host_names': app.host_names or [],
                    'enabled_host_names': app.enabled_host_names or [],
                    'availability_state': app.availability_state,
                    'server_farm_id': app.server_farm_id,
                    'reserved': app.reserved,
                    'is_xenon': app.is_xenon,
                    'hyper_v': app.hyper_v,
                    'last_modified_time_utc': app.last_modified_time_utc.isoformat() if app.last_modified_time_utc else None,
                    'https_only': app.https_only,
                    'tags': dict(app.tags) if app.tags else {}
                }
                web_apps[app.id] = app_dict
            
            logger.info(f"获取到 {len(web_apps)} 个Web应用")
            return web_apps
            
        except Exception as e:
            logger.error(f"获取Web应用失败: {str(e)}")
            return {}
    
    def get_all_web_assets(self) -> Dict[str, Any]:
        """
        获取所有Web应用资源
        
        Returns:
            Dict[str, Any]: 所有Web应用资源信息
        """
        logger.info("开始收集Azure Web应用资源")
        
        web_assets = {
            'app_service_plans': self.get_app_service_plans(),
            'web_apps': self.get_web_apps()
        }
        
        # 统计信息
        total_count = sum(len(assets) for assets in web_assets.values())
        logger.info(f"Azure Web应用资源收集完成，共 {total_count} 个资源")
        
        return web_assets 