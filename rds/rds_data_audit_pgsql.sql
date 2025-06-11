-- RDS Schema Extractor SQL Version for PostgreSQL
-- 此脚本用于提取PostgreSQL数据库的表结构和数据样本

-- 1. 获取所有非系统数据库
SELECT string_agg(DISTINCT
    CONCAT(
        '-- Database: ', datname, E'\n',
        '\c ', datname, E';\n'
    ), ''
) AS database_list
FROM pg_database
WHERE datname NOT IN ('postgres', 'template0', 'template1')
AND datistemplate = false;

-- 2. 获取指定模式中的所有表
-- 替换 ${SCHEMA_NAME} 为实际的模式名 (通常为 'public')
SELECT string_agg(DISTINCT
    CONCAT(
        E'\n-- Table: ', table_name, E'\n',
        '-- Structure (psql client only)', E'\n',
        '\d+ ', table_schema, '.', table_name, E';\n',
        '-- Alternative SQL query for structure', E'\n',
        'SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = ''', table_schema, ''' AND table_name = ''', table_name, ''' ORDER BY ordinal_position;', E'\n',
        '-- Sample Data', E'\n',
        'SELECT * FROM ', table_schema, '.', table_name, ' LIMIT 10;', E'\n'
    ), ''
) AS table_queries
FROM information_schema.tables
WHERE table_schema = '${SCHEMA_NAME}'
AND table_type = 'BASE TABLE';

-- 3. 获取表的详细信息
SELECT
    t.table_schema AS schema_name,
    t.table_name,
    COALESCE(s.n_tup_ins, 0) AS estimated_rows,
    pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
    pg_size_pretty(pg_relation_size(c.oid)) AS table_size,
    pg_size_pretty(pg_total_relation_size(c.oid) - pg_relation_size(c.oid)) AS index_size,
    obj_description(c.oid, 'pg_class') AS table_comment,
    string_agg(
        CONCAT(
            col.column_name, ' ',
            CASE 
                WHEN col.data_type = 'character varying' THEN 
                    CASE WHEN col.character_maximum_length IS NOT NULL 
                         THEN CONCAT('varchar(', col.character_maximum_length, ')')
                         ELSE 'varchar'
                    END
                WHEN col.data_type = 'character' THEN 
                    CASE WHEN col.character_maximum_length IS NOT NULL 
                         THEN CONCAT('char(', col.character_maximum_length, ')')
                         ELSE 'char'
                    END
                WHEN col.data_type = 'numeric' THEN 
                    CASE WHEN col.numeric_precision IS NOT NULL AND col.numeric_scale IS NOT NULL
                         THEN CONCAT('numeric(', col.numeric_precision, ',', col.numeric_scale, ')')
                         ELSE 'numeric'
                    END
                ELSE col.data_type
            END,
            CASE WHEN col.is_nullable = 'NO' THEN ' NOT NULL' ELSE '' END,
            CASE WHEN col.column_default IS NOT NULL THEN CONCAT(' DEFAULT ', col.column_default) ELSE '' END
        ), E'\n    '
        ORDER BY col.ordinal_position
    ) AS columns
FROM information_schema.tables t
JOIN information_schema.columns col
    ON t.table_schema = col.table_schema
    AND t.table_name = col.table_name
LEFT JOIN pg_class c
    ON c.relname = t.table_name
    AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = t.table_schema)
LEFT JOIN pg_stat_user_tables s
    ON s.schemaname = t.table_schema
    AND s.relname = t.table_name
WHERE t.table_schema = '${SCHEMA_NAME}'
AND t.table_type = 'BASE TABLE'
GROUP BY
    t.table_schema,
    t.table_name,
    s.n_tup_ins,
    c.oid;

-- 4. 获取索引信息
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
WHERE schemaname = '${SCHEMA_NAME}'
ORDER BY tablename, indexname;

-- 5. 获取外键约束信息
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
WHERE tc.table_schema = '${SCHEMA_NAME}'
AND tc.constraint_type = 'FOREIGN KEY'
ORDER BY tc.table_name, tc.constraint_name;

-- 6. 获取序列信息
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
WHERE schemaname = '${SCHEMA_NAME}'
ORDER BY sequencename;

-- 7. 获取视图信息
SELECT
    table_schema AS schema_name,
    table_name AS view_name,
    view_definition
FROM information_schema.views
WHERE table_schema = '${SCHEMA_NAME}'
ORDER BY table_name;

-- 使用说明：
-- 1. 将此SQL文件中的 ${SCHEMA_NAME} 替换为要审计的模式名称（通常为 'public'）
-- 2. 可以使用以下命令执行此脚本并将结果保存到文件：
--    psql -h <host> -p <port> -U <user> -d <database> -f rds_data_audit_pgsql.sql > audit_result.txt
--
-- 注意事项：
-- 1. 需要确保用户具有足够的权限访问 information_schema 和系统表
-- 2. 对于大型数据库，获取表大小信息可能需要较长时间
-- 3. Sample Data 查询默认限制为10条记录，可根据需要修改 LIMIT 值
-- 4. PostgreSQL 使用模式(schema)概念，通常默认模式为 'public'
-- 5. 某些查询可能需要根据具体的PostgreSQL版本进行调整
-- 6. 使用 \d+ 命令查看表结构需要在 psql 客户端中执行 