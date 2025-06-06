-- RDS用户权限清单查询脚本
-- 用途：获取RDS实例中的用户权限信息
-- 包含：1. 用户和host清单 2. 详细的用户权限信息

-- 1. 获取所有用户和host清单
SELECT
    user AS '用户名',
    host AS '主机',
    plugin AS '认证插件',
    account_locked AS '账户是否锁定'
FROM mysql.user
ORDER BY user, host;

-- 2. 获取全局权限信息
SELECT
    user AS '用户名',
    host AS '主机',
    CONCAT(
        IF(Select_priv = 'Y', 'SELECT, ', ''),
        IF(Insert_priv = 'Y', 'INSERT, ', ''),
        IF(Update_priv = 'Y', 'UPDATE, ', ''),
        IF(Delete_priv = 'Y', 'DELETE, ', ''),
        IF(Create_priv = 'Y', 'CREATE, ', ''),
        IF(Drop_priv = 'Y', 'DROP, ', ''),
        IF(Reload_priv = 'Y', 'RELOAD, ', ''),
        IF(Shutdown_priv = 'Y', 'SHUTDOWN, ', ''),
        IF(Process_priv = 'Y', 'PROCESS, ', ''),
        IF(File_priv = 'Y', 'FILE, ', ''),
        IF(Grant_priv = 'Y', 'GRANT, ', ''),
        IF(References_priv = 'Y', 'REFERENCES, ', ''),
        IF(Index_priv = 'Y', 'INDEX, ', ''),
        IF(Alter_priv = 'Y', 'ALTER, ', ''),
        IF(Show_db_priv = 'Y', 'SHOW DB, ', ''),
        IF(Super_priv = 'Y', 'SUPER, ', ''),
        IF(Create_tmp_table_priv = 'Y', 'CREATE TEMP TABLE, ', ''),
        IF(Lock_tables_priv = 'Y', 'LOCK TABLES, ', ''),
        IF(Execute_priv = 'Y', 'EXECUTE, ', ''),
        IF(Repl_slave_priv = 'Y', 'REPLICATION SLAVE, ', ''),
        IF(Repl_client_priv = 'Y', 'REPLICATION CLIENT, ', ''),
        IF(Create_view_priv = 'Y', 'CREATE VIEW, ', ''),
        IF(Show_view_priv = 'Y', 'SHOW VIEW, ', ''),
        IF(Create_routine_priv = 'Y', 'CREATE ROUTINE, ', ''),
        IF(Alter_routine_priv = 'Y', 'ALTER ROUTINE, ', ''),
        IF(Create_user_priv = 'Y', 'CREATE USER, ', ''),
        IF(Event_priv = 'Y', 'EVENT, ', ''),
        IF(Trigger_priv = 'Y', 'TRIGGER, ', '')
    ) AS '全局权限'
FROM mysql.user
ORDER BY user, host;

-- 3. 获取数据库级别的权限
SELECT
    db AS '数据库',
    user AS '用户名',
    host AS '主机',
    CONCAT(
        IF(Select_priv = 'Y', 'SELECT, ', ''),
        IF(Insert_priv = 'Y', 'INSERT, ', ''),
        IF(Update_priv = 'Y', 'UPDATE, ', ''),
        IF(Delete_priv = 'Y', 'DELETE, ', ''),
        IF(Create_priv = 'Y', 'CREATE, ', ''),
        IF(Drop_priv = 'Y', 'DROP, ', ''),
        IF(Grant_priv = 'Y', 'GRANT, ', ''),
        IF(References_priv = 'Y', 'REFERENCES, ', ''),
        IF(Index_priv = 'Y', 'INDEX, ', ''),
        IF(Alter_priv = 'Y', 'ALTER, ', ''),
        IF(Create_tmp_table_priv = 'Y', 'CREATE TEMP TABLE, ', ''),
        IF(Lock_tables_priv = 'Y', 'LOCK TABLES, ', ''),
        IF(Create_view_priv = 'Y', 'CREATE VIEW, ', ''),
        IF(Show_view_priv = 'Y', 'SHOW VIEW, ', ''),
        IF(Create_routine_priv = 'Y', 'CREATE ROUTINE, ', ''),
        IF(Alter_routine_priv = 'Y', 'ALTER ROUTINE, ', ''),
        IF(Execute_priv = 'Y', 'EXECUTE, ', ''),
        IF(Event_priv = 'Y', 'EVENT, ', ''),
        IF(Trigger_priv = 'Y', 'TRIGGER, ', '')
    ) AS '数据库权限'
FROM mysql.db
WHERE db NOT IN ('sys', 'mysql', 'information_schema', 'performance_schema')
ORDER BY db, user, host;

-- 4. 获取表级别的权限
SELECT
    db AS '数据库',
    table_name AS '表名',
    user AS '用户名',
    host AS '主机',
    CONCAT(
        IF(Table_priv & 1, 'SELECT, ', ''),
        IF(Table_priv & 2, 'INSERT, ', ''),
        IF(Table_priv & 4, 'UPDATE, ', ''),
        IF(Table_priv & 8, 'DELETE, ', ''),
        IF(Table_priv & 16, 'CREATE, ', ''),
        IF(Table_priv & 32, 'DROP, ', ''),
        IF(Table_priv & 64, 'GRANT, ', ''),
        IF(Table_priv & 128, 'REFERENCES, ', ''),
        IF(Table_priv & 256, 'INDEX, ', ''),
        IF(Table_priv & 512, 'ALTER, ', '')
    ) AS '表权限'
FROM mysql.tables_priv
ORDER BY db, table_name, user, host;

-- 5. 获取列级别的权限
SELECT
    db AS '数据库',
    table_name AS '表名',
    column_name AS '列名',
    user AS '用户名',
    host AS '主机',
    CONCAT(
        IF(Column_priv & 1, 'SELECT, ', ''),
        IF(Column_priv & 2, 'INSERT, ', ''),
        IF(Column_priv & 4, 'UPDATE, ', ''),
        IF(Column_priv & 8, 'REFERENCES, ', '')
    ) AS '列权限'
FROM mysql.columns_priv
ORDER BY db, table_name, column_name, user, host;

-- 6. 获取存储过程和函数的权限
SELECT
    db AS '数据库',
    routine_name AS '存储过程/函数名',
    routine_type AS '类型',
    user AS '用户名',
    host AS '主机',
    CONCAT(
        IF(Proc_priv & 1, 'EXECUTE, ', ''),
        IF(Proc_priv & 2, 'ALTER ROUTINE, ', ''),
        IF(Proc_priv & 4, 'GRANT, ', '')
    ) AS '权限'
FROM mysql.procs_priv
ORDER BY db, routine_name, user, host;
