-- RDS Schema Extractor SQL Version
-- 此脚本用于提取RDS数据库的表结构和数据样本

-- 设置结果输出格式
SET SESSION group_concat_max_len = 1000000;

-- 1. 获取所有非系统数据库
SELECT GROUP_CONCAT(DISTINCT
    CONCAT(
        '-- Database: ', schema_name, '\n',
        'USE ', schema_name, ';\n'
    )
) AS database_list
FROM information_schema.schemata
WHERE schema_name NOT IN ('information_schema', 'performance_schema', 'mysql', 'sys');

-- 2. 获取指定数据库中的所有表
-- 替换 ${DATABASE_NAME} 为实际的数据库名
SELECT GROUP_CONCAT(DISTINCT
    CONCAT(
        '\n-- Table: ', table_name, '\n',
        '-- Structure\n',
        'SHOW CREATE TABLE ', table_schema, '.', table_name, ';\n',
        '-- Sample Data\n',
        'SELECT * FROM ', table_schema, '.', table_name, ' LIMIT 10;\n'
    )
) AS table_queries
FROM information_schema.tables
WHERE table_schema = '${DATABASE_NAME}'
AND table_type = 'BASE TABLE';

-- 3. 获取表的详细信息
SELECT
    t.table_schema AS database_name,
    t.table_name,
    t.table_rows,
    t.data_length,
    t.index_length,
    t.create_time,
    t.update_time,
    GROUP_CONCAT(
        CONCAT(
            c.column_name, ' ',
            c.column_type,
            CASE WHEN c.is_nullable = 'NO' THEN ' NOT NULL' ELSE '' END,
            CASE WHEN c.column_default IS NOT NULL THEN CONCAT(' DEFAULT ', c.column_default) ELSE '' END,
            CASE WHEN c.extra != '' THEN CONCAT(' ', c.extra) ELSE '' END
        )
        ORDER BY c.ordinal_position
    ) AS columns
FROM information_schema.tables t
JOIN information_schema.columns c
    ON t.table_schema = c.table_schema
    AND t.table_name = c.table_name
WHERE t.table_schema = '${DATABASE_NAME}'
AND t.table_type = 'BASE TABLE'
GROUP BY
    t.table_schema,
    t.table_name,
    t.table_rows,
    t.data_length,
    t.index_length,
    t.create_time,
    t.update_time;

-- 4. 获取索引信息
SELECT
    table_schema AS database_name,
    table_name,
    index_name,
    GROUP_CONCAT(column_name ORDER BY seq_in_index) AS index_columns,
    index_type,
    CASE non_unique WHEN 1 THEN 'Non-Unique' ELSE 'Unique' END AS uniqueness
FROM information_schema.statistics
WHERE table_schema = '${DATABASE_NAME}'
GROUP BY
    table_schema,
    table_name,
    index_name,
    index_type,
    non_unique;

-- 使用说明：
-- 1. 将此SQL文件中的 ${DATABASE_NAME} 替换为要审计的数据库名称
-- 2. 可以使用以下命令执行此脚本并将结果保存到文件：
--    mysql -h <host> -P <port> -u <user> -p < rds_data_audit.sql > audit_result.txt
--
-- 注意事项：
-- 1. 需要确保用户具有足够的权限访问 information_schema
-- 2. 对于大型数据库，获取表行数可能需要较长时间
-- 3. Sample Data 查询默认限制为10条记录，可根据需要修改 LIMIT 值
-- 4. 某些查询可能需要根据具体的MySQL版本进行调整
