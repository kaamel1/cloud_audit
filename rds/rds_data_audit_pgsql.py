#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RDS PostgreSQL 数据审计工具
用于提取PostgreSQL数据库的表结构和数据样本
"""

import psycopg2
import argparse
import sys
import os
import logging
from typing import Dict, List, Optional, Tuple
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
logger = logging.getLogger('postgresql-schema-extractor')


class PostgreSQLAuditor:
    def __init__(self, output_dir: str = 'output', sample_limit: int = 10, schema: str = 'public'):
        """
        初始化PostgreSQL审计器
        
        Args:
            output_dir: 输出目录
            sample_limit: 每个表抽样的记录数
            schema: 模式名，默认为'public'
        """
        self.output_dir = output_dir
        self.sample_limit = sample_limit
        self.schema = schema
        self.connection = None
        
        # 创建主输出目录
        os.makedirs(self.output_dir, exist_ok=True)
        
    def connect(self, host: str, port: int, username: str, password: str, database: str):
        """建立数据库连接"""
        try:
            self.connection = psycopg2.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                database=database
            )
            logger.info(f"成功连接到数据库: {database}")
        except Exception as e:
            logger.error(f"连接数据库失败: {e}")
            sys.exit(1)
    
    def disconnect(self):
        """关闭数据库连接"""
        if self.connection:
            self.connection.close()
            logger.info("数据库连接已关闭")
    
    def execute_query(self, query: str) -> List[Dict]:
        """执行查询并返回结果"""
        if not self.connection:
            raise Exception("数据库未连接")
        
        cursor = self.connection.cursor()
        try:
            cursor.execute(query)
            columns = [desc[0] for desc in cursor.description] if cursor.description else []
            rows = cursor.fetchall()
            
            result = []
            for row in rows:
                result.append(dict(zip(columns, row)))
            
            return result
        except Exception as e:
            logger.error(f"查询执行失败: {e}")
            logger.error(f"查询语句: {query}")
            return []
        finally:
            cursor.close()
    
    def get_databases(self) -> List[str]:
        """获取所有非系统数据库"""
        query = """
        SELECT datname
        FROM pg_database
        WHERE datname NOT IN ('postgres', 'template0', 'template1')
        AND datistemplate = false
        ORDER BY datname;
        """
        result = self.execute_query(query)
        return [db['datname'] for db in result]
    
    def get_tables(self) -> List[str]:
        """获取指定模式中的所有表"""
        query = f"""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = '{self.schema}'
        AND table_type = 'BASE TABLE'
        ORDER BY table_name;
        """
        result = self.execute_query(query)
        return [table['table_name'] for table in result]
    
    def get_table_ddl(self, table_name: str) -> Optional[str]:
        """
        获取表的DDL（通过查询表结构信息重构）
        
        Args:
            table_name: 表名
            
        Returns:
            表的DDL语句，如果失败则返回None
        """
        try:
            # 获取表结构
            structure_query = f"""
            SELECT 
                column_name, 
                data_type, 
                is_nullable, 
                column_default,
                character_maximum_length,
                numeric_precision,
                numeric_scale,
                ordinal_position
            FROM information_schema.columns 
            WHERE table_schema = '{self.schema}' 
            AND table_name = '{table_name}' 
            ORDER BY ordinal_position;
            """
            columns = self.execute_query(structure_query)
            
            if not columns:
                return None
            
            # 构建DDL
            ddl_lines = [f"-- Table: {self.schema}.{table_name}"]
            ddl_lines.append(f"CREATE TABLE {self.schema}.{table_name} (")
            
            column_definitions = []
            for col in columns:
                col_def = f"    {col['column_name']} "
                
                # 数据类型
                if col['data_type'] == 'character varying':
                    if col['character_maximum_length']:
                        col_def += f"varchar({col['character_maximum_length']})"
                    else:
                        col_def += "varchar"
                elif col['data_type'] == 'character':
                    if col['character_maximum_length']:
                        col_def += f"char({col['character_maximum_length']})"
                    else:
                        col_def += "char"
                elif col['data_type'] == 'numeric':
                    if col['numeric_precision'] and col['numeric_scale']:
                        col_def += f"numeric({col['numeric_precision']},{col['numeric_scale']})"
                    else:
                        col_def += "numeric"
                else:
                    col_def += col['data_type']
                
                # 是否允许NULL
                if col['is_nullable'] == 'NO':
                    col_def += " NOT NULL"
                
                # 默认值
                if col['column_default']:
                    col_def += f" DEFAULT {col['column_default']}"
                
                column_definitions.append(col_def)
            
            ddl_lines.append(",\n".join(column_definitions))
            ddl_lines.append(");")
            
            # 获取索引信息
            index_query = f"""
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE schemaname = '{self.schema}' AND tablename = '{table_name}'
            AND indexname != '{table_name}_pkey'
            ORDER BY indexname;
            """
            indexes = self.execute_query(index_query)
            
            if indexes:
                ddl_lines.append("\n-- Indexes:")
                for idx in indexes:
                    ddl_lines.append(f"{idx['indexdef']};")
            
            return "\n".join(ddl_lines)
            
        except Exception as e:
            logger.error(f"获取表 {table_name} 的DDL失败: {e}")
            return None
    
    def get_table_sample(self, table_name: str) -> List[Dict]:
        """获取表的样本数据"""
        query = f"SELECT * FROM {self.schema}.{table_name} LIMIT {self.sample_limit};"
        return self.execute_query(query)
    
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
        # 为每个表创建独立的文件夹
        table_dir = os.path.join(db_dir, table)
        os.makedirs(table_dir, exist_ok=True)
        
        # 保存DDL
        ddl_file = os.path.join(table_dir, f"{table}_ddl.sql")
        with open(ddl_file, 'w', encoding='utf-8') as f:
            f.write(ddl)

        # 保存样本数据
        sample_file = os.path.join(table_dir, f"{table}_sample.json")
        with open(sample_file, 'w', encoding='utf-8') as f:
            json.dump(sample_data, f, default=str, indent=2, ensure_ascii=False)
            
        return ddl_file, sample_file
    
    def get_indexes(self) -> List[Dict]:
        """获取索引信息"""
        query = f"""
        SELECT
            schemaname AS schema_name,
            tablename AS table_name,
            indexname AS index_name,
            indexdef AS index_definition,
            CASE 
                WHEN indexdef LIKE '%UNIQUE%' THEN 'Unique'
                ELSE 'Non-Unique'
            END AS uniqueness
        FROM pg_indexes
        WHERE schemaname = '{self.schema}'
        ORDER BY tablename, indexname;
        """
        return self.execute_query(query)
    
    def get_foreign_keys(self) -> List[Dict]:
        """获取外键约束信息"""
        query = f"""
        SELECT
            tc.table_schema AS schema_name,
            tc.table_name,
            tc.constraint_name,
            tc.constraint_type,
            kcu.column_name,
            ccu.table_name AS foreign_table_name,
            ccu.column_name AS foreign_column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
            AND tc.table_schema = kcu.table_schema
        JOIN information_schema.constraint_column_usage ccu
            ON ccu.constraint_name = tc.constraint_name
            AND ccu.table_schema = tc.table_schema
        WHERE tc.table_schema = '{self.schema}'
        AND tc.constraint_type = 'FOREIGN KEY'
        ORDER BY tc.table_name, tc.constraint_name;
        """
        return self.execute_query(query)
    
    def get_sequences(self) -> List[Dict]:
        """获取序列信息"""
        query = f"""
        SELECT
            schemaname AS schema_name,
            sequencename AS sequence_name,
            start_value,
            min_value,
            max_value,
            increment_by,
            cycle,
            cache_size,
            last_value
        FROM pg_sequences
        WHERE schemaname = '{self.schema}'
        ORDER BY sequencename;
        """
        return self.execute_query(query)
    
    def get_views(self) -> List[Dict]:
        """获取视图信息"""
        query = f"""
        SELECT
            table_schema AS schema_name,
            table_name AS view_name,
            view_definition
        FROM information_schema.views
        WHERE table_schema = '{self.schema}'
        ORDER BY table_name;
        """
        return self.execute_query(query)
    
    def save_metadata(self, db_dir: str, database: str):
        """保存数据库元数据信息"""
        metadata = {
            "database_info": {
                "database": database,
                "schema": self.schema,
                "timestamp": datetime.now().isoformat()
            },
            "indexes": self.get_indexes(),
            "foreign_keys": self.get_foreign_keys(),
            "sequences": self.get_sequences(),
            "views": self.get_views()
        }
        
        metadata_file = os.path.join(db_dir, "_metadata.json")
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, default=str, indent=2, ensure_ascii=False)
        
        logger.info(f"已保存数据库元数据到 {metadata_file}")
    
    def extract_schema(self, host: str, port: int, username: str, password: str, 
                      database: str) -> bool:
        """
        主要执行函数
        
        Args:
            host: 数据库主机地址
            port: 数据库端口
            username: 用户名
            password: 密码
            database: 数据库名
            
        Returns:
            是否成功完成提取
        """
        start_time = time.time()
        
        # 连接数据库
        self.connect(host, port, username, password, database)
        
        try:
            logger.info(f"处理数据库: {database}")
            db_dir = self.create_output_structure(database)
            
            # 获取数据库中的所有表
            tables = self.get_tables()
            
            if not tables:
                logger.warning(f"数据库 {database} 的模式 {self.schema} 中没有找到表")
                return False

            logger.info(f"数据库 {database} 的模式 {self.schema} 中找到 {len(tables)} 个表")

            processed_tables = 0
            
            # 处理每个表
            for table in tables:
                logger.info(f"处理表: {self.schema}.{table}")
                try:
                    # 获取表的DDL
                    ddl = self.get_table_ddl(table)
                    if not ddl:
                        logger.warning(f"无法获取表 {self.schema}.{table} 的DDL")
                        continue

                    # 获取表的样本数据
                    sample_data = self.get_table_sample(table)

                    # 保存信息
                    ddl_file, sample_file = self.save_table_info(db_dir, table, ddl, sample_data)
                    logger.info(f"已保存表 {self.schema}.{table} 的DDL到 {ddl_file}")
                    logger.info(f"已保存表 {self.schema}.{table} 的样本数据到 {sample_file}")

                    processed_tables += 1
                    logger.info(f"进度: {processed_tables}/{len(tables)} ({processed_tables/len(tables)*100:.1f}%)")
                except Exception as e:
                    logger.error(f"处理表 {self.schema}.{table} 时出错: {str(e)}")
                    continue

            # 保存元数据
            self.save_metadata(db_dir, database)
            
            end_time = time.time()
            duration = end_time - start_time
            logger.info(f"架构提取完成！共处理了 {processed_tables} 个表，耗时 {duration:.2f} 秒")
            return True

        except Exception as e:
            logger.error(f"执行过程中出错: {str(e)}")
            return False
        finally:
            self.disconnect()
    
    def print_summary(self, host: str, port: int, username: str, password: str, database: str):
        """打印数据库摘要信息"""
        self.connect(host, port, username, password, database)
        
        try:
            print(f"\n=== PostgreSQL 数据库审计摘要 ===")
            print(f"数据库: {database}")
            print(f"模式: {self.schema}")
            print(f"主机: {host}:{port}")
            print("=" * 40)
            
            # 表统计
            tables = self.get_tables()
            print(f"表数量: {len(tables)}")
            
            # 索引统计
            indexes = self.get_indexes()
            print(f"索引数量: {len(indexes)}")
            
            # 外键统计
            foreign_keys = self.get_foreign_keys()
            print(f"外键数量: {len(foreign_keys)}")
            
            # 序列统计
            sequences = self.get_sequences()
            print(f"序列数量: {len(sequences)}")
            
            # 视图统计
            views = self.get_views()
            print(f"视图数量: {len(views)}")
            
            print("=" * 40)
        finally:
            self.disconnect()


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='PostgreSQL数据库审计工具 - 提取PostgreSQL数据库架构和样本数据')
    
    # 连接参数
    parser.add_argument('--host', required=True, help='数据库主机地址')
    parser.add_argument('--port', type=int, default=5432, help='数据库端口 (默认: 5432)')
    parser.add_argument('--username', required=True, help='数据库用户名')
    parser.add_argument('--password', help='数据库密码 (不推荐在命令行中提供，将会提示输入)')
    parser.add_argument('--database', required=True, help='数据库名')
    parser.add_argument('--schema', default='public', help='模式名 (默认: public)')
    
    # 输出参数
    parser.add_argument('--output-dir', default='output', help='输出目录 (默认: output)')
    parser.add_argument('--sample-limit', type=int, default=10, help='每个表的样本数据记录数 (默认: 10)')
    
    # 操作模式
    parser.add_argument('--summary-only', action='store_true', help='仅显示摘要信息')
    
    return parser.parse_args()


def main():
    """主函数"""
    args = parse_arguments()
    
    # 创建审计器实例
    auditor = PostgreSQLAuditor(
        output_dir=args.output_dir,
        sample_limit=args.sample_limit,
        schema=args.schema
    )
    
    # 获取密码
    password = args.password
    if not password:
        password = getpass.getpass("请输入数据库密码: ")
    
    try:
        if args.summary_only:
            # 仅显示摘要
            auditor.print_summary(args.host, args.port, args.username, password, args.database)
        else:
            # 提取架构
            success = auditor.extract_schema(
                host=args.host,
                port=args.port,
                username=args.username,
                password=password,
                database=args.database
            )
            return 0 if success else 1
        
    except Exception as e:
        logger.error(f"执行失败: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 