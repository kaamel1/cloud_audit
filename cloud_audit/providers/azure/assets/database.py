"""Azure数据库资源收集器"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class DatabaseAssetCollector:
    """Azure数据库资源收集器"""
    
    def __init__(self, session):
        """
        初始化数据库资源收集器
        
        Args:
            session: Azure会话对象
        """
        self.session = session
        self.sql_client = session.get_client('sql')
    
    def get_sql_servers(self) -> Dict[str, Any]:
        """
        获取SQL服务器列表
        
        Returns:
            Dict[str, Any]: SQL服务器信息字典，键为SQL服务器ID
        """
        try:
            sql_servers = {}
            for server in self.sql_client.servers.list():
                server_dict = {
                    'id': server.id,
                    'name': server.name,
                    'location': server.location,
                    'resource_group': server.id.split('/')[4] if server.id else None,
                    'version': server.version,
                    'administrator_login': server.administrator_login,
                    'state': server.state,
                    'fully_qualified_domain_name': server.fully_qualified_domain_name,
                    'tags': dict(server.tags) if server.tags else {}
                }
                sql_servers[server.id] = server_dict
            
            logger.info(f"获取到 {len(sql_servers)} 个SQL服务器")
            return sql_servers
            
        except Exception as e:
            logger.error(f"获取SQL服务器列表失败: {str(e)}")
            return {}
    
    def get_sql_databases(self) -> Dict[str, Any]:
        """
        获取SQL数据库列表
        
        Returns:
            Dict[str, Any]: SQL数据库信息字典，键为SQL数据库ID
        """
        try:
            databases = {}
            
            # 首先获取所有SQL服务器
            for server in self.sql_client.servers.list():
                try:
                    resource_group = server.id.split('/')[4]
                    
                    # 获取该服务器下的所有数据库
                    server_databases = self.sql_client.databases.list_by_server(
                        resource_group_name=resource_group,
                        server_name=server.name
                    )
                    
                    for db in server_databases:
                        db_dict = {
                            'id': db.id,
                            'name': db.name,
                            'location': db.location,
                            'server_name': server.name,
                            'resource_group': resource_group,
                            'status': db.status,
                            'collation': db.collation,
                            'creation_date': db.creation_date.isoformat() if db.creation_date else None,
                            'current_service_objective_name': db.current_service_objective_name,
                            'database_id': db.database_id,
                            'edition': getattr(db, 'edition', None) or getattr(db, 'sku', {}).get('tier', None),
                            'max_size_bytes': db.max_size_bytes,
                            'tags': dict(db.tags) if db.tags else {}
                        }
                        databases[db.id] = db_dict
                        
                except Exception as e:
                    logger.warning(f"获取SQL服务器 {server.name} 的数据库失败: {str(e)}")
                    continue
            
            logger.info(f"获取到 {len(databases)} 个SQL数据库")
            return databases
            
        except Exception as e:
            logger.error(f"获取SQL数据库列表失败: {str(e)}")
            return {}
    
    def get_all_database_assets(self) -> Dict[str, Any]:
        """
        获取所有数据库资源
        
        Returns:
            Dict[str, Any]: 所有数据库资源信息
        """
        logger.info("开始收集Azure数据库资源")
        
        database_assets = {
            'sql_servers': self.get_sql_servers(),
            'sql_databases': self.get_sql_databases()
        }
        
        # 统计信息
        total_count = sum(len(assets) for assets in database_assets.values())
        logger.info(f"Azure数据库资源收集完成，共 {total_count} 个资源")
        
        return database_assets 