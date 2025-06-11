#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RDS用户权限清单查询脚本 (PostgreSQL版本)
用途：获取RDS实例中的用户权限信息
包含：1. 用户清单 2. 详细的用户权限信息 3. IP访问控制信息
"""

import psycopg2
import pandas as pd
from typing import Dict, List, Optional
import logging
import sys
from datetime import datetime
import argparse
import json


class PostgreSQLPermissionAuditor:
    """PostgreSQL权限审计工具"""
    
    def __init__(self, host: str, port: int, database: str, username: str, password: str):
        """
        初始化数据库连接参数
        
        Args:
            host: 数据库主机地址
            port: 数据库端口
            database: 数据库名称
            username: 用户名
            password: 密码
        """
        self.host = host
        self.port = port
        self.database = database
        self.username = username
        self.password = password
        self.connection = None
        
        # 配置日志
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def connect(self) -> bool:
        """建立数据库连接"""
        try:
            self.connection = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.username,
                password=self.password
            )
            self.logger.info("数据库连接成功")
            return True
        except Exception as e:
            self.logger.error(f"数据库连接失败: {e}")
            return False
    
    def disconnect(self):
        """关闭数据库连接"""
        if self.connection:
            self.connection.close()
            self.logger.info("数据库连接已关闭")
    
    def execute_query(self, query: str) -> Optional[pd.DataFrame]:
        """执行SQL查询并返回DataFrame"""
        try:
            df = pd.read_sql_query(query, self.connection)
            return df
        except Exception as e:
            self.logger.error(f"查询执行失败: {e}")
            return None
    
    def get_user_list(self) -> Optional[pd.DataFrame]:
        """1. 获取所有用户清单"""
        query = """
        SELECT
            rolname AS "用户名",
            CASE 
                WHEN rolsuper THEN '超级用户'
                WHEN rolcreaterole THEN '可创建角色'
                WHEN rolcreatedb THEN '可创建数据库'
                WHEN rolreplication THEN '复制权限'
                WHEN rolcanlogin THEN '可登录'
                ELSE '普通用户'
            END AS "用户类型",
            CASE WHEN rolcanlogin THEN '是' ELSE '否' END AS "可登录",
            CASE WHEN NOT rolvaliduntil IS NULL THEN rolvaliduntil::text ELSE '无限制' END AS "有效期",
            CASE WHEN rolconnlimit = -1 THEN '无限制' ELSE rolconnlimit::text END AS "连接限制"
        FROM pg_roles
        ORDER BY rolname;
        """
        return self.execute_query(query)
    
    def get_system_privileges(self) -> Optional[pd.DataFrame]:
        """2. 获取用户的系统级权限"""
        query = """
        SELECT
            rolname AS "用户名",
            CONCAT(
                CASE WHEN rolsuper THEN 'SUPERUSER, ' ELSE '' END,
                CASE WHEN rolcreaterole THEN 'CREATEROLE, ' ELSE '' END,
                CASE WHEN rolcreatedb THEN 'CREATEDB, ' ELSE '' END,
                CASE WHEN rolreplication THEN 'REPLICATION, ' ELSE '' END,
                CASE WHEN rolcanlogin THEN 'LOGIN, ' ELSE '' END,
                CASE WHEN rolbypassrls THEN 'BYPASSRLS, ' ELSE '' END
            ) AS "系统权限"
        FROM pg_roles
        ORDER BY rolname;
        """
        return self.execute_query(query)
    
    def get_database_privileges(self) -> Optional[pd.DataFrame]:
        """3. 获取数据库级别的权限"""
        query = """
        SELECT
            d.datname AS "数据库",
            r.rolname AS "用户名",
            ARRAY_TO_STRING(
                ARRAY(
                    SELECT privilege_type
                    FROM information_schema.table_privileges tp
                    WHERE tp.grantee = r.rolname
                    AND tp.table_catalog = d.datname
                    UNION
                    SELECT 'CONNECT'
                    FROM pg_database pd
                    WHERE pd.datname = d.datname
                    AND has_database_privilege(r.rolname, pd.datname, 'CONNECT')
                    UNION
                    SELECT 'CREATE'
                    FROM pg_database pd
                    WHERE pd.datname = d.datname
                    AND has_database_privilege(r.rolname, pd.datname, 'CREATE')
                    UNION
                    SELECT 'TEMPORARY'
                    FROM pg_database pd
                    WHERE pd.datname = d.datname
                    AND has_database_privilege(r.rolname, pd.datname, 'TEMPORARY')
                ), ', '
            ) AS "数据库权限"
        FROM pg_database d
        CROSS JOIN pg_roles r
        WHERE d.datname NOT IN ('template0', 'template1', 'postgres')
        AND (
            has_database_privilege(r.rolname, d.datname, 'CONNECT') OR
            has_database_privilege(r.rolname, d.datname, 'CREATE') OR
            has_database_privilege(r.rolname, d.datname, 'TEMPORARY')
        )
        ORDER BY d.datname, r.rolname;
        """
        return self.execute_query(query)
    
    def get_schema_privileges(self) -> Optional[pd.DataFrame]:
        """4. 获取schema级别的权限"""
        query = """
        SELECT
            current_database() AS "数据库",
            nspname AS "Schema",
            r.rolname AS "用户名",
            ARRAY_TO_STRING(
                ARRAY(
                    SELECT 'USAGE'
                    WHERE has_schema_privilege(r.rolname, n.nspname, 'USAGE')
                    UNION
                    SELECT 'CREATE'
                    WHERE has_schema_privilege(r.rolname, n.nspname, 'CREATE')
                ), ', '
            ) AS "Schema权限"
        FROM pg_namespace n
        CROSS JOIN pg_roles r
        WHERE n.nspname NOT IN ('information_schema', 'pg_catalog', 'pg_toast')
        AND n.nspname NOT LIKE 'pg_temp_%'
        AND n.nspname NOT LIKE 'pg_toast_temp_%'
        AND (
            has_schema_privilege(r.rolname, n.nspname, 'USAGE') OR
            has_schema_privilege(r.rolname, n.nspname, 'CREATE')
        )
        ORDER BY nspname, r.rolname;
        """
        return self.execute_query(query)
    
    def get_table_privileges(self) -> Optional[pd.DataFrame]:
        """5. 获取表级别的权限"""
        query = """
        SELECT
            t.table_catalog AS "数据库",
            t.table_schema AS "Schema",
            t.table_name AS "表名",
            t.grantee AS "用户名",
            STRING_AGG(t.privilege_type, ', ' ORDER BY t.privilege_type) AS "表权限",
            STRING_AGG(
                CASE WHEN t.is_grantable = 'YES' THEN t.privilege_type || '(可授权)' ELSE NULL END, 
                ', ' ORDER BY t.privilege_type
            ) AS "可授权权限"
        FROM information_schema.table_privileges t
        WHERE t.table_schema NOT IN ('information_schema', 'pg_catalog')
        GROUP BY t.table_catalog, t.table_schema, t.table_name, t.grantee
        ORDER BY t.table_schema, t.table_name, t.grantee;
        """
        return self.execute_query(query)
    
    def get_column_privileges(self) -> Optional[pd.DataFrame]:
        """6. 获取列级别的权限"""
        query = """
        SELECT
            c.table_catalog AS "数据库",
            c.table_schema AS "Schema", 
            c.table_name AS "表名",
            c.column_name AS "列名",
            c.grantee AS "用户名",
            STRING_AGG(c.privilege_type, ', ' ORDER BY c.privilege_type) AS "列权限",
            STRING_AGG(
                CASE WHEN c.is_grantable = 'YES' THEN c.privilege_type || '(可授权)' ELSE NULL END, 
                ', ' ORDER BY c.privilege_type
            ) AS "可授权权限"
        FROM information_schema.column_privileges c
        WHERE c.table_schema NOT IN ('information_schema', 'pg_catalog')
        GROUP BY c.table_catalog, c.table_schema, c.table_name, c.column_name, c.grantee
        ORDER BY c.table_schema, c.table_name, c.column_name, c.grantee;
        """
        return self.execute_query(query)
    
    def get_routine_privileges(self) -> Optional[pd.DataFrame]:
        """7. 获取函数和存储过程的权限"""
        query = """
        SELECT
            r.routine_catalog AS "数据库",
            r.routine_schema AS "Schema",
            r.routine_name AS "函数/存储过程名",
            rt.routine_type AS "类型",
            r.grantee AS "用户名",
            STRING_AGG(r.privilege_type, ', ' ORDER BY r.privilege_type) AS "权限",
            STRING_AGG(
                CASE WHEN r.is_grantable = 'YES' THEN r.privilege_type || '(可授权)' ELSE NULL END, 
                ', ' ORDER BY r.privilege_type
            ) AS "可授权权限"
        FROM information_schema.routine_privileges r
        LEFT JOIN information_schema.routines rt ON (
            r.routine_catalog = rt.routine_catalog 
            AND r.routine_schema = rt.routine_schema 
            AND r.routine_name = rt.routine_name
        )
        WHERE r.routine_schema NOT IN ('information_schema', 'pg_catalog')
        GROUP BY r.routine_catalog, r.routine_schema, r.routine_name, rt.routine_type, r.grantee
        ORDER BY r.routine_schema, r.routine_name, r.grantee;
        """
        return self.execute_query(query)
    
    def get_sequence_privileges(self) -> Optional[pd.DataFrame]:
        """8. 获取序列的权限"""
        query = """
        SELECT
            current_database() AS "数据库",
            schemaname AS "Schema",
            sequencename AS "序列名",
            r.rolname AS "用户名",
            ARRAY_TO_STRING(
                ARRAY(
                    SELECT 'USAGE'
                    WHERE has_sequence_privilege(r.rolname, s.schemaname||'.'||s.sequencename, 'USAGE')
                    UNION
                    SELECT 'SELECT'
                    WHERE has_sequence_privilege(r.rolname, s.schemaname||'.'||s.sequencename, 'SELECT')
                    UNION
                    SELECT 'UPDATE'
                    WHERE has_sequence_privilege(r.rolname, s.schemaname||'.'||s.sequencename, 'UPDATE')
                ), ', '
            ) AS "序列权限"
        FROM pg_sequences s
        CROSS JOIN pg_roles r
        WHERE s.schemaname NOT IN ('information_schema', 'pg_catalog')
        AND (
            has_sequence_privilege(r.rolname, s.schemaname||'.'||s.sequencename, 'USAGE') OR
            has_sequence_privilege(r.rolname, s.schemaname||'.'||s.sequencename, 'SELECT') OR
            has_sequence_privilege(r.rolname, s.schemaname||'.'||s.sequencename, 'UPDATE')
        )
        ORDER BY s.schemaname, s.sequencename, r.rolname;
        """
        return self.execute_query(query)
    
    def get_role_memberships(self) -> Optional[pd.DataFrame]:
        """9. 获取角色成员关系"""
        query = """
        SELECT
            r.rolname AS "角色",
            m.rolname AS "成员用户",
            CASE WHEN a.admin_option THEN '是' ELSE '否' END AS "管理员权限"
        FROM pg_roles r
        JOIN pg_auth_members a ON r.oid = a.roleid
        JOIN pg_roles m ON m.oid = a.member
        ORDER BY r.rolname, m.rolname;
        """
        return self.execute_query(query)
    
    def get_hba_rules(self) -> Optional[pd.DataFrame]:
        """10. 获取HBA访问控制规则 (PostgreSQL 10+)"""
        query = """
        SELECT 
            line_number AS "规则行号",
            type AS "连接类型",
            CASE 
                WHEN database IS NULL OR database = '{}' THEN '未指定'
                WHEN database = '{all}' THEN '所有数据库'
                WHEN CARDINALITY(database) > 0 THEN ARRAY_TO_STRING(database, ', ')
                ELSE '未指定'
            END AS "数据库",
            CASE 
                WHEN user_name IS NULL OR user_name = '{}' THEN '未指定'
                WHEN user_name = '{all}' THEN '所有用户'
                WHEN CARDINALITY(user_name) > 0 THEN ARRAY_TO_STRING(user_name, ', ')
                ELSE '未指定'
            END AS "用户",
            COALESCE(address, '本地连接') AS "IP地址/网段",
            COALESCE(netmask, '') AS "子网掩码", 
            auth_method AS "认证方式",
            COALESCE(ARRAY_TO_STRING(options, ', '), '') AS "选项",
            COALESCE(error, '') AS "配置错误"
        FROM pg_hba_file_rules 
        WHERE line_number IS NOT NULL
        ORDER BY line_number;
        """
        return self.execute_query(query)
    
    def get_network_settings(self) -> Optional[pd.DataFrame]:
        """11. 获取网络监听配置"""
        query = """
        SELECT 
            name AS "配置项",
            setting AS "当前值",
            unit AS "单位",
            category AS "类别",
            short_desc AS "说明"
        FROM pg_settings 
        WHERE name IN ('listen_addresses', 'port', 'max_connections', 'ssl', 'ssl_cert_file', 'ssl_key_file')
        ORDER BY name;
        """
        return self.execute_query(query)
    
    def audit_all_permissions(self) -> Dict[str, pd.DataFrame]:
        """执行完整的权限审计"""
        results = {}
        
        if not self.connect():
            return results
        
        try:
            self.logger.info("开始执行权限审计...")
            
            # 执行所有查询
            queries = [
                ("用户清单", self.get_user_list),
                ("系统级权限", self.get_system_privileges),
                ("数据库级权限", self.get_database_privileges),
                ("Schema级权限", self.get_schema_privileges),
                ("表级权限", self.get_table_privileges),
                ("列级权限", self.get_column_privileges),
                ("函数存储过程权限", self.get_routine_privileges),
                ("序列权限", self.get_sequence_privileges),
                ("角色成员关系", self.get_role_memberships),
                ("HBA访问控制规则", self.get_hba_rules),
                ("网络监听配置", self.get_network_settings)
            ]
            
            for query_name, query_func in queries:
                self.logger.info(f"正在执行查询: {query_name}")
                df = query_func()
                if df is not None:
                    results[query_name] = df
                    self.logger.info(f"查询完成: {query_name}, 结果行数: {len(df)}")
                else:
                    self.logger.warning(f"查询失败: {query_name}")
            
            self.logger.info("权限审计完成")
            
        finally:
            self.disconnect()
        
        return results
    
    def export_to_excel(self, results: Dict[str, pd.DataFrame], filename: str = None):
        """导出结果到Excel文件"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"postgresql_permission_audit_{timestamp}.xlsx"
        
        try:
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                for sheet_name, df in results.items():
                    # Excel工作表名称长度限制
                    safe_sheet_name = sheet_name[:31] if len(sheet_name) > 31 else sheet_name
                    df.to_excel(writer, sheet_name=safe_sheet_name, index=False)
            
            self.logger.info(f"结果已导出到: {filename}")
            return filename
        except Exception as e:
            self.logger.error(f"导出Excel失败: {e}")
            return None
    
    def export_to_json(self, results: Dict[str, pd.DataFrame], filename: str = None):
        """导出结果到JSON文件"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"postgresql_permission_audit_{timestamp}.json"
        
        try:
            json_results = {}
            for key, df in results.items():
                json_results[key] = df.to_dict('records')
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(json_results, f, ensure_ascii=False, indent=2, default=str)
            
            self.logger.info(f"结果已导出到: {filename}")
            return filename
        except Exception as e:
            self.logger.error(f"导出JSON失败: {e}")
            return None
    
    def print_summary(self, results: Dict[str, pd.DataFrame]):
        """打印审计结果摘要"""
        print("\n" + "="*50)
        print("PostgreSQL权限审计结果摘要")
        print("="*50)
        
        for query_name, df in results.items():
            print(f"\n{query_name}:")
            print(f"  记录数: {len(df)}")
            if not df.empty:
                print(f"  列数: {len(df.columns)}")
                print(f"  列名: {', '.join(df.columns)}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='PostgreSQL权限审计工具')
    parser.add_argument('--host', required=True, help='数据库主机地址')
    parser.add_argument('--port', type=int, default=5432, help='数据库端口 (默认: 5432)')
    parser.add_argument('--database', required=True, help='数据库名称')
    parser.add_argument('--username', required=True, help='用户名')
    parser.add_argument('--password', required=True, help='密码')
    parser.add_argument('--output', choices=['excel', 'json', 'both'], default='excel', 
                       help='输出格式 (默认: excel)')
    parser.add_argument('--filename', help='输出文件名前缀')
    
    args = parser.parse_args()
    
    # 创建审计器实例
    auditor = PostgreSQLPermissionAuditor(
        host=args.host,
        port=args.port,
        database=args.database,
        username=args.username,
        password=args.password
    )
    
    # 执行审计
    results = auditor.audit_all_permissions()
    
    if not results:
        print("审计失败，未获取到任何数据")
        sys.exit(1)
    
    # 打印摘要
    auditor.print_summary(results)
    
    # 导出结果
    if args.output in ['excel', 'both']:
        excel_file = auditor.export_to_excel(results, 
                                           f"{args.filename}.xlsx" if args.filename else None)
        if excel_file:
            print(f"\nExcel文件已保存: {excel_file}")
    
    if args.output in ['json', 'both']:
        json_file = auditor.export_to_json(results, 
                                         f"{args.filename}.json" if args.filename else None)
        if json_file:
            print(f"JSON文件已保存: {json_file}")


if __name__ == "__main__":
    main() 