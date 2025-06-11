-- RDS用户权限清单查询脚本 (PostgreSQL版本)
-- 用途：获取RDS实例中的用户权限信息
-- 包含：1. 用户清单 2. 详细的用户权限信息 3. IP访问控制信息

-- 1. 获取所有用户清单
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

-- 2. 获取用户的系统级权限
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

-- 3. 获取数据库级别的权限
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

-- 4. 获取schema级别的权限
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

-- 5. 获取表级别的权限
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

-- 6. 获取列级别的权限
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

-- 7. 获取函数和存储过程的权限
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

-- 8. 获取序列的权限
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

-- 9. 获取角色成员关系
SELECT
    r.rolname AS "角色",
    m.rolname AS "成员用户",
    CASE WHEN a.admin_option THEN '是' ELSE '否' END AS "管理员权限"
FROM pg_roles r
JOIN pg_auth_members a ON r.oid = a.roleid
JOIN pg_roles m ON m.oid = a.member
ORDER BY r.rolname, m.rolname;

-- 10. 获取HBA访问控制规则 (PostgreSQL 10+)
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

-- 11. 获取网络监听配置
SELECT 
    name AS "配置项",
    setting AS "当前值",
    unit AS "单位",
    category AS "类别",
    short_desc AS "说明"
FROM pg_settings 
WHERE name IN ('listen_addresses', 'port', 'max_connections', 'ssl', 'ssl_cert_file', 'ssl_key_file')
ORDER BY name; 