#!/usr/bin/env python3
"""
RDS Schema Extractor (Simple Version)

此脚本用于连接RDS数据库，提取所有数据库的表结构和数据样本。
输出将保存在指定的目录结构中。
"""

import os
import sys
import argparse
import logging
import pymysql
from typing import List, Dict, Any, Optional, Tuple
import json
from datetime import datetime
import getpass
import time

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('rds-schema-extractor')

class RDSSchemaExtractor:
    def __init__(self, output_dir: str = 'output', sample_limit: int = 10):
        """
        初始化RDS架构提取器

        Args:
            output_dir: 输出目录
            sample_limit: 每个表抽样的记录数
        """
        self.output_dir = output_dir
        self.sample_limit = sample_limit

        # 创建主输出目录
        os.makedirs(self.output_dir, exist_ok=True)

    def connect_to_db(self, host: str, port: int, user: str, password: str) -> Optional[pymysql.Connection]:
        """
        连接到数据库

        Args:
            host: 数据库主机地址
            port: 数据库端口
            user: 用户名
            password: 密码

        Returns:
            数据库连接对象，如果连接失败则返回None
        """
        try:
            connection = pymysql.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                charset='utf8mb4',
                connect_timeout=10
            )
            logger.info(f"成功连接到数据库 {host}:{port}")
            return connection
        except Exception as e:
            logger.error(f"连接数据库失败: {str(e)}")
            return None

    def get_all_databases(self, connection: pymysql.Connection) -> List[str]:
        """
        获取所有数据库名称
        
        Args:
            connection: 数据库连接对象
            
        Returns:
            数据库名称列表
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute("SHOW DATABASES")
                # 排除系统数据库
                system_dbs = ['information_schema', 'performance_schema', 'mysql', 'sys']
                return [db[0] for db in cursor.fetchall() if db[0] not in system_dbs]
        except Exception as e:
            logger.error(f"获取数据库列表失败: {str(e)}")
            return []

    def get_tables_in_database(self, connection: pymysql.Connection, database: str) -> List[str]:
        """
        获取指定数据库中的所有表
        
        Args:
            connection: 数据库连接对象
            database: 数据库名称
            
        Returns:
            表名列表
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute(f"USE `{database}`")
                cursor.execute("SHOW TABLES")
                return [table[0] for table in cursor.fetchall()]
        except Exception as e:
            logger.error(f"获取数据库 {database} 的表列表失败: {str(e)}")
            return []

    def get_table_ddl(self, connection: pymysql.Connection, database: str, table: str) -> Optional[str]:
        """
        获取表的DDL
        
        Args:
            connection: 数据库连接对象
            database: 数据库名称
            table: 表名
            
        Returns:
            表的DDL语句，如果失败则返回None
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute(f"SHOW CREATE TABLE `{database}`.`{table}`")
                result = cursor.fetchone()
                return result[1] if result else None
        except Exception as e:
            logger.error(f"获取表 {database}.{table} 的DDL失败: {str(e)}")
            return None

    def get_table_sample(self, connection: pymysql.Connection, database: str, table: str) -> List[Dict]:
        """
        获取表的数据样本
        
        Args:
            connection: 数据库连接对象
            database: 数据库名称
            table: 表名
            
        Returns:
            表的样本数据列表
        """
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(f"SELECT * FROM `{database}`.`{table}` LIMIT {self.sample_limit}")
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"获取表 {database}.{table} 的样本数据失败: {str(e)}")
            return []

    def create_output_structure(self, database: str) -> str:
        """
        创建输出目录结构
        
        Args:
            database: 数据库名称
            
        Returns:
            创建的目录路径
        """
        db_dir = os.path.join(self.output_dir, database)
        os.makedirs(db_dir, exist_ok=True)
        return db_dir

    def save_table_info(self, db_dir: str, table: str, ddl: str, sample_data: List[Dict]) -> Tuple[str, str]:
        """
        保存表的DDL和样本数据
        
        Args:
            db_dir: 数据库目录
            table: 表名
            ddl: DDL语句
            sample_data: 样本数据
            
        Returns:
            保存的DDL文件路径和样本数据文件路径
        """
        # 保存DDL
        ddl_file = os.path.join(db_dir, f"{table}_ddl.sql")
        with open(ddl_file, 'w', encoding='utf-8') as f:
            f.write(ddl)

        # 保存样本数据
        sample_file = os.path.join(db_dir, f"{table}_sample.json")
        with open(sample_file, 'w', encoding='utf-8') as f:
            json.dump(sample_data, f, default=str, indent=2, ensure_ascii=False)
            
        return ddl_file, sample_file

    def extract_schema(self, host: str, port: int, user: str, password: str, 
                      specific_databases: List[str] = None) -> bool:
        """
        主要执行函数
        
        Args:
            host: 数据库主机地址
            port: 数据库端口
            user: 用户名
            password: 密码
            specific_databases: 指定要处理的数据库列表，如果为None则处理所有数据库
            
        Returns:
            是否成功完成提取
        """
        start_time = time.time()
        
        # 连接数据库
        connection = self.connect_to_db(host, port, user, password)
        if not connection:
            return False
        
        try:
            # 获取所有数据库
            all_databases = self.get_all_databases(connection)
            if not all_databases:
                logger.warning("未找到任何数据库")
                return False
                
            # 如果指定了特定数据库，则只处理这些数据库
            databases = specific_databases if specific_databases else all_databases
            # 确保指定的数据库存在
            databases = [db for db in databases if db in all_databases]
            
            if not databases:
                logger.warning("没有找到指定的数据库")
                return False
                
            logger.info(f"将处理以下数据库: {', '.join(databases)}")
            
            total_tables = 0
            processed_tables = 0
            
            # 统计总表数
            for database in databases:
                tables = self.get_tables_in_database(connection, database)
                total_tables += len(tables)
            
            # 处理每个数据库
            for database in databases:
                logger.info(f"处理数据库: {database}")
                db_dir = self.create_output_structure(database)
                
                # 获取数据库中的所有表
                tables = self.get_tables_in_database(connection, database)
                
                if not tables:
                    logger.warning(f"数据库 {database} 中没有找到表")
                    continue

                logger.info(f"数据库 {database} 中找到 {len(tables)} 个表")

                # 处理每个表
                for table in tables:
                    logger.info(f"处理表: {database}.{table}")
                    try:
                        # 获取表的DDL
                        ddl = self.get_table_ddl(connection, database, table)
                        if not ddl:
                            logger.warning(f"无法获取表 {database}.{table} 的DDL")
                            continue

                        # 获取表的样本数据
                        sample_data = self.get_table_sample(connection, database, table)

                        # 保存信息
                        ddl_file, sample_file = self.save_table_info(db_dir, table, ddl, sample_data)
                        logger.info(f"已保存表 {database}.{table} 的DDL到 {ddl_file}")
                        logger.info(f"已保存表 {database}.{table} 的样本数据到 {sample_file}")

                        processed_tables += 1
                        logger.info(f"进度: {processed_tables}/{total_tables} ({processed_tables/total_tables*100:.1f}%)")
                    except Exception as e:
                        logger.error(f"处理表 {database}.{table} 时出错: {str(e)}")
                        continue

            connection.close()
            end_time = time.time()
            duration = end_time - start_time
            logger.info(f"架构提取完成！共处理了 {len(databases)} 个数据库，{processed_tables} 个表，耗时 {duration:.2f} 秒")
            return True

        except Exception as e:
            logger.error(f"执行过程中出错: {str(e)}")
            if connection:
                connection.close()
            return False

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='RDS Schema Extractor - 提取RDS数据库架构和样本数据')

    # 连接参数
    parser.add_argument('--host', required=True, help='数据库主机地址')
    parser.add_argument('--port', type=int, default=3306, help='数据库端口 (默认: 3306)')
    parser.add_argument('--user', required=True, help='数据库用户名')
    parser.add_argument('--password', help='数据库密码 (不推荐在命令行中提供，将会提示输入)')

    # 输出参数
    parser.add_argument('--output-dir', default='output', help='输出目录 (默认: output)')
    parser.add_argument('--sample-limit', type=int, default=10, help='每个表的样本数据记录数 (默认: 10)')

    # 过滤参数
    parser.add_argument('--databases', nargs='+', help='指定要处理的数据库列表 (默认: 所有)')

    return parser.parse_args()

def main():
    """主函数"""
    args = parse_arguments()

    # 创建提取器
    extractor = RDSSchemaExtractor(
        output_dir=args.output_dir,
        sample_limit=args.sample_limit
    )

    # 获取密码
    password = args.password
    if not password:
        password = getpass.getpass("请输入数据库密码: ")

    # 提取架构
    success = extractor.extract_schema(
        host=args.host,
        port=args.port,
        user=args.user,
        password=password,
        specific_databases=args.databases
    )

    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
