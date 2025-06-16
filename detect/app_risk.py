import requests
import socket
import subprocess
import os
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import nmap
import time
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AppRiskDetector:
    def __init__(self):
        # 风险规则数据库（从你的SQL数据中提取）
        self.risk_rules = [
            {
                "id": 1,
                "name": "Redis 未授权访问",
                "desc": "Redis 服务未设置密码，绑定在公网且未做访问控制",
                "level": 1,
                "request_type": "TCP",
                "type": "未授权访问",
                "path": "redis://<target_ip>:6379",
                "payload": "INFO",
                "flag": "# Server"
            },
            {
                "id": 2,
                "name": "Tomcat 以 root 用户运行",
                "desc": "Tomcat 服务使用 root 超级用户权限运行",
                "level": 1,
                "request_type": "AGENT",
                "type": "权限过高",
                "path": "本地进程检查",
                "payload": "ps -ef | grep 'java.*tomcat' | grep -v grep",
                "flag": "root"
            },
            {
                "id": 4,
                "name": "Tomcat 管理后台弱口令",
                "desc": "Tomcat manager 应用存在默认口令",
                "level": 1,
                "request_type": "GET",
                "type": "弱口令",
                "path": "/manager/html",
                "payload": "Basic dG9tY2F0OnRvbWNhdA==",
                "flag": "Apache Tomcat Web Application Manager"
            },
            {
                "id": 5,
                "name": "MySQL 允许远程 root 用户登录",
                "desc": "数据库配置允许 root 用户从任意主机登录",
                "level": 1,
                "request_type": "TCP",
                "type": "配置错误",
                "path": "mysql://<target_ip>:3306",
                "payload": "SELECT user, host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost', '127.0.0.1');",
                "flag": "root"
            },
            {
                "id": 6,
                "name": "SSH 允许 root 用户直接登录",
                "desc": "SSH 服务配置文件中 PermitRootLogin 设置为 yes",
                "level": 2,
                "request_type": "AGENT",
                "type": "配置错误",
                "path": "/etc/ssh/sshd_config",
                "payload": "cat /etc/ssh/sshd_config | grep \"^PermitRootLogin\"",
                "flag": "PermitRootLogin yes"
            },
            {
                "id": 7,
                "name": "WebLogic 控制台公网暴露",
                "desc": "WebLogic 的管理控制台/console页面可以直接从公网访问",
                "level": 2,
                "request_type": "GET",
                "type": "服务暴露",
                "path": "/console",
                "payload": "",
                "flag": "Oracle WebLogic Server Administration Console"
            },
            {
                "id": 8,
                "name": "错误页面泄露敏感信息",
                "desc": "Web应用在发生错误时，返回的页面中包含了详细的堆栈轨迹",
                "level": 3,
                "request_type": "GET",
                "type": "信息泄露",
                "path": "/a.jsp",
                "payload": "",
                "flag": "java.lang.Exception"
            },
            {
                "id": 9,
                "name": "RabbitMQ 默认guest用户可访问",
                "desc": "RabbitMQ 默认的 guest/guest 用户未被删除或禁用",
                "level": 2,
                "request_type": "GET",
                "type": "弱口令",
                "path": "http://<target_ip>:15672/api/whoami",
                "payload": "Basic Z3Vlc3Q6Z3Vlc3Q=",
                "flag": '"name":"guest"'
            },
            {
                "id": 10,
                "name": "Web 服务未启用 HTTPS",
                "desc": "网站登录页面或包含敏感信息的页面使用 HTTP 明文传输",
                "level": 2,
                "request_type": "GET",
                "type": "明文传输",
                "path": "/login",
                "payload": "",
                "flag": '<form action="http://'
            },
            {
                "id": 11,
                "name": "Log4j2 JNDI 远程代码执行漏洞",
                "desc": "应用使用了存在漏洞的 Log4j2 版本",
                "level": 1,
                "request_type": "GET",
                "type": "远程代码执行",
                "path": "/",
                "payload": "${jndi:ldap://dnslog.cn/log4j}",
                "flag": "DNSLog Record"
            },
            {
                "id": 12,
                "name": "Jenkins 未授权访问",
                "desc": "Jenkins 服务未配置任何认证",
                "level": 1,
                "request_type": "GET",
                "type": "未授权访问",
                "path": "/",
                "payload": "",
                "flag": "Manage Jenkins"
            },
            {
                "id": 13,
                "name": "FTP 允许匿名登录",
                "desc": "FTP 服务器配置允许匿名(anonymous)用户登录",
                "level": 2,
                "request_type": "TCP",
                "type": "弱口令",
                "path": "ftp://<target_ip>:21",
                "payload": "USER anonymous\nPASS anonymous",
                "flag": "230 Login successful"
            },
            {
                "id": 14,
                "name": "Nginx 默认欢迎页面暴露",
                "desc": "Nginx 安装后未修改或移除默认的欢迎页面",
                "level": 3,
                "request_type": "GET",
                "type": "信息泄露",
                "path": "/",
                "payload": "",
                "flag": "Welcome to nginx!"
            },
            {
                "id": 15,
                "name": "Struts2 S2-016 远程代码执行",
                "desc": "应用使用了存在漏洞的 Struts2 版本",
                "level": 1,
                "request_type": "GET",
                "type": "远程代码执行",
                "path": "/index.action?redirect:default.action?redirect:${#context[#x]=true,#context[#x]}",
                "payload": "Location: default.action?true",
                "flag": "true"
            },
            {
                "id": 16,
                "name": "ActiveMQ 任意文件写入漏洞",
                "desc": "低版本 ActiveMQ 存在未授权访问",
                "level": 1,
                "request_type": "PUT",
                "type": "任意文件写入",
                "path": "/fileserver/test.txt",
                "payload": "This is a test file.",
                "flag": "204 No Content"
            },
            {
                "id": 17,
                "name": "MongoDB 未授权访问",
                "desc": "MongoDB 服务未开启认证(auth)，且绑定在公网",
                "level": 1,
                "request_type": "TCP",
                "type": "未授权访问",
                "path": "mongodb://<target_ip>:27017",
                "payload": "listDatabases",
                "flag": "admin"
            },
            {
                "id": 18,
                "name": ".git 目录泄露",
                "desc": "Web 部署时将 .git 目录一同部署到服务器",
                "level": 1,
                "request_type": "GET",
                "type": "信息泄露",
                "path": "/.git/config",
                "payload": "",
                "flag": "[core]"
            },
            {
                "id": 19,
                "name": "Shiro RememberMe 反序列化漏洞",
                "desc": "应用使用 Shiro 框架且 RememberMe 功能的加密密钥为硬编码默认值",
                "level": 1,
                "request_type": "GET",
                "type": "反序列化",
                "path": "/",
                "payload": "Cookie: rememberMe=",
                "flag": "rememberMe=deleteMe"
            },
            {
                "id": 20,
                "name": "phpMyAdmin 弱口令",
                "desc": "服务器上部署的 phpMyAdmin 存在空密码或常见弱口令",
                "level": 1,
                "request_type": "GET",
                "type": "弱口令",
                "path": "/phpmyadmin/",
                "payload": "",
                "flag": "phpMyAdmin"
            },
            {
                "id": 21,
                "name": "WebLogic WLS-WSAT XML 反序列化",
                "desc": "低版本 WebLogic 的 WLS-WSAT 组件存在反序列化漏洞",
                "level": 1,
                "request_type": "POST",
                "type": "反序列化",
                "path": "/wls-wsat/CoordinatorPortType",
                "payload": '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><void/></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>',
                "flag": "wls-wsat"
            },
            {
                "id": 26,
                "name": "Web服务器版本信息泄露",
                "desc": "HTTP响应头中包含了Web服务器的详细版本号",
                "level": 3,
                "request_type": "GET",
                "type": "信息泄露",
                "path": "/",
                "payload": "",
                "flag": "Server: Apache/2."
            },
            {
                "id": 27,
                "name": "Redis 监听在公网地址",
                "desc": "Redis服务监听在0.0.0.0，接受来自任何网络接口的连接",
                "level": 1,
                "request_type": "AGENT",
                "type": "服务暴露",
                "path": "网络连接状态",
                "payload": "netstat -tlnp | grep redis-server",
                "flag": "0.0.0.0:6379"
            },
            {
                "id": 28,
                "name": "Java JMX 远程端口暴露且未授权",
                "desc": "Java应用开启了JMX远程监控，但未对其端口进行访问控制",
                "level": 1,
                "request_type": "TCP",
                "type": "未授权访问",
                "path": "jmx://<target_ip>:9999",
                "payload": "connect",
                "flag": "Successfully connected"
            },
            {
                "id": 31,
                "name": "Docker Daemon API 未授权访问",
                "desc": "Docker守护进程的远程API端口(2375)暴露在公网且未配置TLS认证",
                "level": 1,
                "request_type": "GET",
                "type": "未授权访问",
                "path": "http://<target_ip>:2375/version",
                "payload": "",
                "flag": '"ApiVersion"'
            }
        ]
        
        self.detection_results = []

    def detect_redis_unauthorized(self, target_host="127.0.0.1", port=6379):
        """检测Redis未授权访问"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target_host, port))
            if result == 0:
                # 尝试发送INFO命令
                sock.send(b"INFO\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if "# Server" in response:
                    return {
                        "risk_id": 1,
                        "risk_name": "Redis 未授权访问",
                        "risk_level": 1,
                        "status": "存在风险",
                        "details": f"Redis服务在 {target_host}:{port} 可未授权访问",
                        "evidence": response[:200]
                    }
            sock.close()
        except Exception as e:
            pass
        return None

    def detect_mongodb_unauthorized(self, target_host="127.0.0.1", port=27017):
        """检测MongoDB未授权访问"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target_host, port))
            if result == 0:
                # MongoDB连接测试
                sock.send(b'\x3a\x00\x00\x00\xa3\x01\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x6c\x69\x73\x74\x44\x61\x74\x61\x62\x61\x73\x65\x73\x00\x00\x00\x00\x00')
                response = sock.recv(1024)
                sock.close()
                
                if b'admin' in response:
                    return {
                        "risk_id": 17,
                        "risk_name": "MongoDB 未授权访问",
                        "risk_level": 1,
                        "status": "存在风险",
                        "details": f"MongoDB服务在 {target_host}:{port} 可未授权访问",
                        "evidence": f"Port {port} is open and accessible"
                    }
            sock.close()
        except Exception as e:
            pass
        return None

    def detect_tomcat_root_user(self):
        """检测Tomcat是否以root用户运行"""
        try:
            if os.name == 'nt':  # Windows
                cmd = "tasklist /FI \"IMAGENAME eq java.exe\" /FO CSV"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if "java.exe" in result.stdout:
                    # 在Windows上检查是否有Tomcat相关进程
                    return {
                        "risk_id": 2,
                        "risk_name": "Tomcat 以 root 用户运行",
                        "risk_level": 1,
                        "status": "需要进一步检查",
                        "details": "检测到Java进程，需要确认是否为Tomcat且以root权限运行",
                        "evidence": result.stdout
                    }
            else:  # Linux/Unix
                cmd = "ps -ef | grep 'java.*tomcat' | grep -v grep"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if line.startswith('root '):
                            return {
                                "risk_id": 2,
                                "risk_name": "Tomcat 以 root 用户运行",
                                "risk_level": 1,
                                "status": "存在风险",
                                "details": "Tomcat进程以root用户运行",
                                "evidence": line
                            }
        except Exception as e:
            pass
        return None

    def detect_ssh_root_login(self):
        """检测SSH是否允许root直接登录"""
        try:
            if os.name != 'nt':  # Linux/Unix
                cmd = "grep \"^PermitRootLogin\" /etc/ssh/sshd_config"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if "PermitRootLogin yes" in result.stdout:
                    return {
                        "risk_id": 6,
                        "risk_name": "SSH 允许 root 用户直接登录",
                        "risk_level": 2,
                        "status": "存在风险",
                        "details": "SSH配置允许root用户直接登录",
                        "evidence": result.stdout.strip()
                    }
        except Exception as e:
            pass
        return None

    def detect_tomcat_weak_password(self, base_url="http://127.0.0.1:8080"):
        """检测Tomcat管理后台弱口令"""
        try:
            url = urljoin(base_url, "/manager/html")
            headers = {
                'Authorization': 'Basic dG9tY2F0OnRvbWNhdA==',  # tomcat:tomcat
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            if "Apache Tomcat Web Application Manager" in response.text:
                return {
                    "risk_id": 4,
                    "risk_name": "Tomcat 管理后台弱口令",
                    "risk_level": 1,
                    "status": "存在风险",
                    "details": f"Tomcat管理后台存在默认弱口令 tomcat:tomcat",
                    "evidence": f"URL: {url}, Status: {response.status_code}"
                }
        except Exception as e:
            pass
        return None

    def detect_weblogic_console(self, base_url="http://127.0.0.1:7001"):
        """检测WebLogic控制台暴露"""
        try:
            url = urljoin(base_url, "/console")
            response = requests.get(url, timeout=10, verify=False)
            if "Oracle WebLogic Server Administration Console" in response.text:
                return {
                    "risk_id": 7,
                    "risk_name": "WebLogic 控制台公网暴露",
                    "risk_level": 2,
                    "status": "存在风险",
                    "details": f"WebLogic控制台在 {url} 可直接访问",
                    "evidence": f"URL: {url}, Status: {response.status_code}"
                }
        except Exception as e:
            pass
        return None

    def detect_rabbitmq_guest(self, base_url="http://127.0.0.1:15672"):
        """检测RabbitMQ默认guest用户"""
        try:
            url = urljoin(base_url, "/api/whoami")
            headers = {
                'Authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q=',  # guest:guest
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            if '"name":"guest"' in response.text:
                return {
                    "risk_id": 9,
                    "risk_name": "RabbitMQ 默认guest用户可访问",
                    "risk_level": 2,
                    "status": "存在风险",
                    "details": f"RabbitMQ管理界面存在默认guest用户",
                    "evidence": f"URL: {url}, Status: {response.status_code}"
                }
        except Exception as e:
            pass
        return None

    def detect_http_instead_https(self, base_url="http://127.0.0.1:8080"):
        """检测Web服务是否使用HTTP而非HTTPS"""
        try:
            # 检查登录页面
            login_urls = ["/login", "/admin", "/user/login", "/auth/login"]
            for login_path in login_urls:
                url = urljoin(base_url, login_path)
                try:
                    response = requests.get(url, timeout=5, verify=False)
                    if response.status_code == 200 and '<form action="http://' in response.text:
                        return {
                            "risk_id": 10,
                            "risk_name": "Web 服务未启用 HTTPS",
                            "risk_level": 2,
                            "status": "存在风险",
                            "details": f"登录页面使用HTTP明文传输",
                            "evidence": f"URL: {url}, Form action contains http://"
                        }
                except:
                    continue
        except Exception as e:
            pass
        return None

    def detect_mysql_remote_root(self, target_host="127.0.0.1", port=3306):
        """检测MySQL是否允许远程root登录"""
        try:
            # 尝试连接MySQL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target_host, port))
            if result == 0:
                return {
                    "risk_id": 5,
                    "risk_name": "MySQL 允许远程 root 用户登录",
                    "risk_level": 1,
                    "status": "需要进一步检查",
                    "details": f"MySQL服务在 {target_host}:{port} 可连接，需要验证root用户权限",
                    "evidence": f"Port {port} is open"
                }
            sock.close()
        except Exception as e:
            pass
        return None

    def detect_log4j_vulnerability(self, base_url="http://127.0.0.1:8080"):
        """检测Log4j2漏洞"""
        try:
            # 构造Log4j2测试payload
            payload = "${jndi:ldap://dnslog.cn/log4j}"
            headers = {
                'User-Agent': payload,
                'X-Forwarded-For': payload,
                'X-Real-IP': payload
            }
            
            response = requests.get(base_url, headers=headers, timeout=10, verify=False)
            # 这里需要配合DNSLog服务来验证是否真的存在漏洞
            # 实际检测中应该使用可控的DNSLog服务
            
            return {
                "risk_id": 11,
                "risk_name": "Log4j2 JNDI 远程代码执行漏洞",
                "risk_level": 1,
                "status": "需要进一步验证",
                "details": "已发送Log4j2测试payload，需要检查DNSLog记录",
                "evidence": f"Payload sent to {base_url}"
            }
        except Exception as e:
            pass
        return None

    def detect_jenkins_unauthorized(self, base_url="http://127.0.0.1:8080"):
        """检测Jenkins未授权访问"""
        try:
            response = requests.get(base_url, timeout=10, verify=False)
            if "Manage Jenkins" in response.text:
                return {
                    "risk_id": 12,
                    "risk_name": "Jenkins 未授权访问",
                    "risk_level": 1,
                    "status": "存在风险",
                    "details": f"Jenkins服务在 {base_url} 可未授权访问",
                    "evidence": f"URL: {base_url}, Status: {response.status_code}"
                }
        except Exception as e:
            pass
        return None

    def detect_ftp_anonymous(self, target_host="127.0.0.1", port=21):
        """检测FTP匿名登录"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target_host, port))
            if result == 0:
                return {
                    "risk_id": 13,
                    "risk_name": "FTP 允许匿名登录",
                    "risk_level": 2,
                    "status": "需要进一步检查",
                    "details": f"FTP服务在 {target_host}:{port} 可连接，需要验证匿名登录",
                    "evidence": f"Port {port} is open"
                }
            sock.close()
        except Exception as e:
            pass
        return None

    def detect_nginx_default_page(self, base_url="http://127.0.0.1:80"):
        """检测Nginx默认欢迎页面"""
        try:
            response = requests.get(base_url, timeout=10, verify=False)
            if "Welcome to nginx!" in response.text:
                return {
                    "risk_id": 14,
                    "risk_name": "Nginx 默认欢迎页面暴露",
                    "risk_level": 3,
                    "status": "存在风险",
                    "details": f"Nginx默认欢迎页面在 {base_url} 可访问",
                    "evidence": f"URL: {base_url}, Status: {response.status_code}"
                }
        except Exception as e:
            pass
        return None

    def detect_struts2_s2016(self, base_url="http://127.0.0.1:8080"):
        """检测Struts2 S2-016漏洞"""
        try:
            payload = "/index.action?redirect:default.action?redirect:${#context[#x]=true,#context[#x]}"
            url = urljoin(base_url, payload)
            response = requests.get(url, timeout=10, verify=False, allow_redirects=False)
            
            if "Location: default.action?true" in str(response.headers):
                return {
                    "risk_id": 15,
                    "risk_name": "Struts2 S2-016 远程代码执行",
                    "risk_level": 1,
                    "status": "存在风险",
                    "details": f"Struts2 S2-016漏洞在 {base_url} 存在",
                    "evidence": f"URL: {url}, Redirect Location: {response.headers.get('Location', '')}"
                }
        except Exception as e:
            pass
        return None

    def detect_activemq_file_write(self, base_url="http://127.0.0.1:8161"):
        """检测ActiveMQ任意文件写入漏洞"""
        try:
            url = urljoin(base_url, "/fileserver/test.txt")
            headers = {
                'Content-Type': 'text/plain',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.put(url, data="This is a test file.", headers=headers, timeout=10, verify=False)
            if response.status_code == 204:
                return {
                    "risk_id": 16,
                    "risk_name": "ActiveMQ 任意文件写入漏洞",
                    "risk_level": 1,
                    "status": "存在风险",
                    "details": f"ActiveMQ fileserver在 {base_url} 可写入文件",
                    "evidence": f"URL: {url}, Status: {response.status_code}"
                }
        except Exception as e:
            pass
        return None

    def detect_git_exposure(self, base_url="http://127.0.0.1:8080"):
        """检测.git目录泄露"""
        try:
            url = urljoin(base_url, "/.git/config")
            response = requests.get(url, timeout=10, verify=False)
            if "[core]" in response.text:
                return {
                    "risk_id": 18,
                    "risk_name": ".git 目录泄露",
                    "risk_level": 1,
                    "status": "存在风险",
                    "details": f".git目录在 {url} 可访问",
                    "evidence": f"URL: {url}, Status: {response.status_code}"
                }
        except Exception as e:
            pass
        return None

    def detect_shiro_rememberme(self, base_url="http://127.0.0.1:8080"):
        """检测Shiro RememberMe反序列化漏洞"""
        try:
            # 构造Shiro RememberMe测试Cookie
            rememberme_cookie = "rememberMe=deleteMe"
            headers = {
                'Cookie': rememberme_cookie,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(base_url, headers=headers, timeout=10, verify=False)
            if "rememberMe=deleteMe" in response.headers.get('Set-Cookie', ''):
                return {
                    "risk_id": 19,
                    "risk_name": "Shiro RememberMe 反序列化漏洞",
                    "risk_level": 1,
                    "status": "需要进一步验证",
                    "details": f"Shiro RememberMe功能在 {base_url} 存在，需要验证密钥",
                    "evidence": f"URL: {base_url}, Cookie: {rememberme_cookie}"
                }
        except Exception as e:
            pass
        return None

    def detect_phpmyadmin_weak_password(self, base_url="http://127.0.0.1:80"):
        """检测phpMyAdmin弱口令"""
        try:
            url = urljoin(base_url, "/phpmyadmin/")
            response = requests.get(url, timeout=10, verify=False)
            if "phpMyAdmin" in response.text:
                return {
                    "risk_id": 20,
                    "risk_name": "phpMyAdmin 弱口令",
                    "risk_level": 1,
                    "status": "需要进一步检查",
                    "details": f"phpMyAdmin在 {url} 可访问，需要验证弱口令",
                    "evidence": f"URL: {url}, Status: {response.status_code}"
                }
        except Exception as e:
            pass
        return None

    def detect_weblogic_wls_wsat(self, base_url="http://127.0.0.1:7001"):
        """检测WebLogic WLS-WSAT反序列化漏洞"""
        try:
            url = urljoin(base_url, "/wls-wsat/CoordinatorPortType")
            payload = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><void/></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>'
            headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.post(url, data=payload, headers=headers, timeout=10, verify=False)
            if "wls-wsat" in response.text:
                return {
                    "risk_id": 21,
                    "risk_name": "WebLogic WLS-WSAT XML 反序列化",
                    "risk_level": 1,
                    "status": "需要进一步验证",
                    "details": f"WebLogic WLS-WSAT在 {url} 存在，需要验证反序列化漏洞",
                    "evidence": f"URL: {url}, Status: {response.status_code}"
                }
        except Exception as e:
            pass
        return None

    def detect_web_server_version(self, base_url="http://127.0.0.1:8080"):
        """检测Web服务器版本信息泄露"""
        try:
            response = requests.get(base_url, timeout=10, verify=False)
            server_header = response.headers.get('Server', '')
            
            if server_header and ('Apache/' in server_header or 'nginx/' in server_header or 'IIS/' in server_header):
                return {
                    "risk_id": 26,
                    "risk_name": "Web服务器版本信息泄露",
                    "risk_level": 3,
                    "status": "存在风险",
                    "details": f"Web服务器版本信息在响应头中泄露",
                    "evidence": f"Server: {server_header}"
                }
        except Exception as e:
            pass
        return None

    def detect_redis_public_binding(self):
        """检测Redis是否监听在公网地址"""
        try:
            if os.name != 'nt':  # Linux/Unix
                cmd = "netstat -tlnp | grep redis-server"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if "0.0.0.0:6379" in result.stdout:
                    return {
                        "risk_id": 27,
                        "risk_name": "Redis 监听在公网地址",
                        "risk_level": 1,
                        "status": "存在风险",
                        "details": "Redis服务监听在0.0.0.0:6379，接受所有网络接口连接",
                        "evidence": result.stdout.strip()
                    }
        except Exception as e:
            pass
        return None

    def detect_jmx_unauthorized(self, target_host="127.0.0.1", port=9999):
        """检测Java JMX远程端口未授权访问"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target_host, port))
            if result == 0:
                return {
                    "risk_id": 28,
                    "risk_name": "Java JMX 远程端口暴露且未授权",
                    "risk_level": 1,
                    "status": "需要进一步检查",
                    "details": f"JMX端口 {port} 在 {target_host} 开放，需要验证访问控制",
                    "evidence": f"Port {port} is open"
                }
            sock.close()
        except Exception as e:
            pass
        return None

    def detect_docker_unauthorized(self, base_url="http://127.0.0.1:2375"):
        """检测Docker Daemon API未授权访问"""
        try:
            url = urljoin(base_url, "/version")
            response = requests.get(url, timeout=10, verify=False)
            if '"ApiVersion"' in response.text:
                return {
                    "risk_id": 31,
                    "risk_name": "Docker Daemon API 未授权访问",
                    "risk_level": 1,
                    "status": "存在风险",
                    "details": f"Docker Daemon API在 {url} 可未授权访问",
                    "evidence": f"URL: {url}, Status: {response.status_code}"
                }
        except Exception as e:
            pass
        return None

    def scan_common_ports(self, target_host="127.0.0.1"):
        """扫描常见端口"""
        try:
            nm = nmap.PortScanner()
            common_ports = "21,22,23,25,53,80,110,143,443,993,995,1433,1521,3306,3389,5432,6379,8080,8443,27017,7001,8161,15672,2375,9999"
            nm.scan(hosts=target_host, arguments=f"-sSV -Pn -p {common_ports} -T4")
            
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'service': nm[host][proto][port]['name'],
                                'product': nm[host][proto][port]['product'],
                                'version': nm[host][proto][port]['version']
                            })
            
            return open_ports
        except Exception as e:
            return []

    def detect_all_risks(self, target_host="127.0.0.1", web_base_url="http://127.0.0.1:8080"):
        """执行所有风险检测"""
        print("开始应用风险检测...")
        
        results = []
        
        # 1. 端口扫描
        print("正在扫描端口...")
        open_ports = self.scan_common_ports(target_host)
        
        # 2. 根据开放端口进行针对性检测
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            # Redis检测
            if service == 'redis' or port == 6379:
                result = self.detect_redis_unauthorized(target_host, port)
                if result:
                    results.append(result)
            
            # MySQL检测
            if service == 'mysql' or port == 3306:
                result = self.detect_mysql_remote_root(target_host, port)
                if result:
                    results.append(result)
            
            # MongoDB检测
            if service == 'mongodb' or port == 27017:
                result = self.detect_mongodb_unauthorized(target_host, port)
                if result:
                    results.append(result)
            
            # FTP检测
            if service == 'ftp' or port == 21:
                result = self.detect_ftp_anonymous(target_host, port)
                if result:
                    results.append(result)
            
            # JMX检测
            if port == 9999:
                result = self.detect_jmx_unauthorized(target_host, port)
                if result:
                    results.append(result)
        
        # 3. Web应用检测
        print("正在检测Web应用风险...")
        web_tests = [
            (self.detect_tomcat_weak_password, "http://127.0.0.1:8080"),
            (self.detect_jenkins_unauthorized, "http://127.0.0.1:8080"),
            (self.detect_git_exposure, "http://127.0.0.1:8080"),
            (self.detect_web_server_version, "http://127.0.0.1:8080"),
            (self.detect_log4j_vulnerability, "http://127.0.0.1:8080"),
            (self.detect_weblogic_console, "http://127.0.0.1:7001"),
            (self.detect_rabbitmq_guest, "http://127.0.0.1:15672"),
            (self.detect_http_instead_https, "http://127.0.0.1:8080"),
            (self.detect_nginx_default_page, "http://127.0.0.1:80"),
            (self.detect_struts2_s2016, "http://127.0.0.1:8080"),
            (self.detect_activemq_file_write, "http://127.0.0.1:8161"),
            (self.detect_shiro_rememberme, "http://127.0.0.1:8080"),
            (self.detect_phpmyadmin_weak_password, "http://127.0.0.1:80"),
            (self.detect_weblogic_wls_wsat, "http://127.0.0.1:7001"),
            (self.detect_docker_unauthorized, "http://127.0.0.1:2375")
        ]
        
        for test_func, test_url in web_tests:
            try:
                result = test_func(test_url)
                if result:
                    results.append(result)
            except Exception as e:
                print(f"检测 {test_func.__name__} 时出错: {e}")
        
        # 4. 本地系统检测
        print("正在检测本地系统风险...")
        local_tests = [
            self.detect_tomcat_root_user,
            self.detect_ssh_root_login,
            self.detect_redis_public_binding
        ]
        
        for test_func in local_tests:
            try:
                result = test_func()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"检测 {test_func.__name__} 时出错: {e}")
        
        print(f"风险检测完成，发现 {len(results)} 个风险")
        return results

    def generate_report(self, results):
        """生成检测报告"""
        report = {
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_risks": len(results),
            "high_risks": len([r for r in results if r['risk_level'] == 1]),
            "medium_risks": len([r for r in results if r['risk_level'] == 2]),
            "low_risks": len([r for r in results if r['risk_level'] == 3]),
            "risks": results
        }
        return report


def app_risk_detect(data):
    """主检测函数，与现有架构集成"""
    print("开始应用风险检测...")
    print(f"接收到的数据: {data}")
    
    detector = AppRiskDetector()
    
    # 从info中获取目标信息，确保使用嵌套结构
    info = data.get('info', {})
    target_host = info.get("target_host", info.get("ipAddress", "127.0.0.1"))
    web_base_url = info.get("web_base_url", f"http://{target_host}:8080")
    
    print(f"目标主机: {target_host}, Web基础URL: {web_base_url}")
    
    # 获取MAC地址，优先使用macAddress字段
    mac_address = info.get('macAddress')
    if not mac_address and 'mac_address' in info:
        mac_address = info.get('mac_address')  # 兼容不同的字段名
    
    # 执行检测
    results = detector.detect_all_risks(target_host, web_base_url)
    
    # 生成报告
    report = detector.generate_report(results)
    
    # 获取主机标识符，用于后端数据关联
    # 优先使用MAC地址，如果没有则尝试使用主机名，再没有则使用IP地址
    host_identifier = target_host  # 默认使用IP地址
    
    if not mac_address:
        mac_address = info.get('hostName', target_host)
        print(f"警告: 消息中缺少macAddress字段，使用替代标识: {mac_address}")
    
    print(f"使用的主机标识符: {host_identifier}")
    print(f"使用的MAC地址: {mac_address}")
    
    # 构建返回结果
    result_data = []
    for risk in report.get('risks', []):
        risk_data = {
            "appriskId": risk.get('risk_id', 0),
            "isVulnerable": 1,  # 1表示存在风险
            "resultEvidence": risk.get('evidence', ''),
            "hostIdentifier": host_identifier,  # IP地址作为主机标识符
            "macAddress": mac_address  # 添加MAC地址字段
        }
        result_data.append(risk_data)
    
    # 构建返回数据，确保包含info字段
    return_data = {
        "info": {
            "macAddress": mac_address,
            "hostIdentifier": host_identifier,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "hostName": info.get("hostName", ""),
            "id": info.get("id", 0)
        },
        "data": result_data
    }
    
    print(f"返回数据结构: {return_data}")
    return json.dumps(return_data)


if __name__ == "__main__":
    # 测试代码
    detector = AppRiskDetector()
    results = detector.detect_all_risks()
    
    print("\n=== 应用风险检测报告 ===")
    print(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"发现风险数量: {len(results)}")
    
    for i, risk in enumerate(results, 1):
        print(f"\n{i}. {risk['risk_name']}")
        print(f"   风险等级: {risk['risk_level']}")
        print(f"   状态: {risk['status']}")
        print(f"   详情: {risk['details']}")
        print(f"   证据: {risk['evidence'][:100]}...")
