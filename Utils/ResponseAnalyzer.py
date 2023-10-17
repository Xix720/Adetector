import urllib
import re


class ResponseAnalyzer:
    def __init__(self, response, payloads):
        self.response = response
        self.payloads = payloads

    # 检查response中是否存在payload，如果存在，表示可能存在XSS漏洞
    def is_xss_vulnerable(self):
        if self.response.status_code == 200:
            encoded_payload = urllib.parse.quote(self.payloads)
            if encoded_payload in urllib.parse.quote(self.response.text):
                return True
            else:
                return False

    # sql注入检测
    def is_sql_injection_vulnerable(self):
        sql_injection_patterns = [
            r"SQL syntax.*MySQL",
            r"SQL syntax",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Error executing an SQL statement",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Error.*ORA-\d{5}",
            r"Oracle error",
            r"Microsoft OLE DB Provider for Oracle",
            r"Microsoft ODBC for Oracle",
            r"java.sql.SQLException",
            r"DB2 SQL error:",
            r"Sybase message:",
            r"Unclosed quotation mark after the character string",
            r"SQL injection vulnerability",
            r"SQL command not properly ended"
        ]

        if self.response.status_code == 200:
            for error in sql_injection_patterns:
                if error.lower() in self.response.text.lower():
                    return True
            return False
        return False

    # 目录遍历漏洞检测
    def is_directory_traversal_vulnerable(self):
        # 用于检测目录遍历漏洞的特征列表
        directory_traversal_patterns = [
            r"\.\./",
            r"root:",
            r"boot.ini",
            r"[boot loader]",
            r"system32",
            r"win.ini",
            r"passwd",
            r"etc/hosts",
            r"etc/shadow",
            r"Directory of",
            r"Volume Serial Number is",
            r"total \d+",
            r"dr-xr-xr-x",
            r"\<\?xml version",
        ]

        if self.response.status_code == 200:
            for pattern in directory_traversal_patterns:
                if pattern.lower() in self.response.text.lower():
                    return True
        return False
