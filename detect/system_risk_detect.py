import platform
import uuid

import psutil
import socket
import subprocess
import time
import datetime
import requests
import re
import logging
import os
import json
from collections import defaultdict

# 配置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class HostRiskDetector:
    """个人主机风险探测工具"""

    def __init__(self):
        self.results = defaultdict(dict)
        self.risk_levels = {
            "critical": "严重风险",
            "high": "高风险",
            "medium": "中风险",
            "low": "低风险",
            "info": "信息",
        }

    def detect_all_risks(self):
        """执行所有风险检测"""
        self.check_time_sync()
        self.check_ip_forwarding()
        self.check_promiscuous_mode()
        self.check_suspicious_connections()
        self.check_high_risk_ports()
        self.check_firewall_status()
        self.check_system_resources()
        self.check_disk_health()

        return self.results

    def check_time_sync(self):
        """检查服务器时间同步"""
        try:
            # 获取NTP服务器时间
            ntp_server = "pool.ntp.org"
            ntp_response = requests.get(f"http://worldtimeapi.org/api/ip")
            ntp_time = datetime.datetime.fromisoformat(
                ntp_response.json()["datetime"].replace("Z", "+00:00")
            )

            # 获取本地时间
            local_time = datetime.datetime.now(datetime.timezone.utc)

            # 计算时间差（秒）
            time_diff = abs((ntp_time - local_time).total_seconds())

            if time_diff > 300:  # 超过5分钟
                self.results["time_sync"] = {
                    "status": "risk",
                    "level": "high",
                    "message": f"系统时间与NTP服务器不同步，相差约{int(time_diff)}秒",
                    "suggestion": "请配置系统时间同步或手动调整系统时间",
                }
            else:
                self.results["time_sync"] = {
                    "status": "normal",
                    "message": f"系统时间与NTP服务器同步，相差约{int(time_diff)}秒",
                }
        except Exception as e:
            self.results["time_sync"] = {
                "status": "error",
                "message": f"时间同步检查失败: {str(e)}",
            }

    def check_ip_forwarding(self):
        """检查IP转发功能是否开启"""
        os_type = platform.system().lower()

        try:
            if os_type == "linux":
                # 检查Linux系统的IP转发设置
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    ip_forward = f.read().strip()

                if ip_forward == "1":
                    self.results["ip_forwarding"] = {
                        "status": "risk",
                        "level": "high",
                        "message": "IP转发功能已开启，可能存在安全风险",
                        "suggestion": "除非有特殊需求，否则应关闭IP转发功能",
                    }
                else:
                    self.results["ip_forwarding"] = {
                        "status": "normal",
                        "message": "IP转发功能已关闭",
                    }
            elif os_type == "windows":
                # 检查Windows系统的IP转发设置
                cmd = "reg query HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                if "REG_DWORD" in result.stdout and "0x1" in result.stdout:
                    self.results["ip_forwarding"] = {
                        "status": "risk",
                        "level": "high",
                        "message": "IP转发功能已开启，可能存在安全风险",
                        "suggestion": "除非有特殊需求，否则应关闭IP转发功能",
                    }
                else:
                    self.results["ip_forwarding"] = {
                        "status": "normal",
                        "message": "IP转发功能已关闭",
                    }
            else:
                self.results["ip_forwarding"] = {
                    "status": "unknown",
                    "message": f"不支持的操作系统: {platform.system()}",
                }
        except Exception as e:
            self.results["ip_forwarding"] = {
                "status": "error",
                "message": f"IP转发检查失败: {str(e)}",
            }

    def check_promiscuous_mode(self):
        """检查网卡是否处于混杂模式"""
        os_type = platform.system().lower()

        try:
            if os_type == "linux":
                # 检查Linux系统的网卡混杂模式
                cmd = "ip link show"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                promiscuous_interfaces = []
                for line in result.stdout.splitlines():
                    if "PROMISC" in line:
                        interface = line.split(":")[1].strip()
                        promiscuous_interfaces.append(interface)

                if promiscuous_interfaces:
                    self.results["promiscuous_mode"] = {
                        "status": "risk",
                        "level": "high",
                        "message": f"以下网卡处于混杂模式: {', '.join(promiscuous_interfaces)}",
                        "suggestion": "除非有特殊需求，否则应禁用网卡的混杂模式",
                    }
                else:
                    self.results["promiscuous_mode"] = {
                        "status": "normal",
                        "message": "未检测到网卡处于混杂模式",
                    }
            elif os_type == "windows":
                # 检查Windows系统的网卡混杂模式
                cmd = "netsh interface show interface"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                # 由于Windows不直接显示混杂模式，这里简化处理
                self.results["promiscuous_mode"] = {
                    "status": "normal",
                    "message": "Windows系统下无法直接检测混杂模式，请手动检查网络适配器设置",
                }
            else:
                self.results["promiscuous_mode"] = {
                    "status": "unknown",
                    "message": f"不支持的操作系统: {platform.system()}",
                }
        except Exception as e:
            self.results["promiscuous_mode"] = {
                "status": "error",
                "message": f"混杂模式检查失败: {str(e)}",
            }

    def check_suspicious_connections(self):
        """检查可疑网络连接"""
        suspicious_connections = []

        try:
            # 定义已知的高风险IP地址或域名列表
            suspicious_ips = [
                "127.0.0.1",  # 本地回环地址，通常不应该有外部连接到此
                "0.0.0.0",  # 通常不应该有外部连接到此
                "255.255.255.255",  # 广播地址
                # 可以添加更多已知的恶意IP
            ]

            # 定义高风险端口
            suspicious_ports = [
                21,  # FTP
                22,  # SSH
                23,  # Telnet
                25,  # SMTP
                135,
                137,
                138,
                139,  # Windows SMB
                445,  # Windows SMB
                3389,  # RDP
                5900,  # VNC
                8080,
                8000,  # 常见Web服务器端口
                # 可以添加更多高风险端口
            ]

            # 获取所有网络连接
            connections = psutil.net_connections(kind="inet")

            for conn in connections:
                # 检查远程地址
                if conn.raddr and conn.raddr.ip in suspicious_ips:
                    suspicious_connections.append(
                        {
                            "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                            "status": conn.status,
                            "reason": "连接到可疑IP地址",
                        }
                    )

                # 检查远程端口
                if conn.raddr and conn.raddr.port in suspicious_ports:
                    suspicious_connections.append(
                        {
                            "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                            "status": conn.status,
                            "reason": "连接到高风险端口",
                        }
                    )

            if suspicious_connections:
                self.results["suspicious_connections"] = {
                    "status": "risk",
                    "level": "high",
                    "message": f"检测到{len(suspicious_connections)}个可疑网络连接",
                    "details": suspicious_connections,
                    "suggestion": "检查并终止不必要的网络连接，确保只连接到可信的服务器",
                }
            else:
                self.results["suspicious_connections"] = {
                    "status": "normal",
                    "message": "未检测到可疑网络连接",
                }
        except Exception as e:
            self.results["suspicious_connections"] = {
                "status": "error",
                "message": f"可疑连接检查失败: {str(e)}",
            }

    def check_high_risk_ports(self):
        """检查开放的高危端口"""
        open_high_risk_ports = []

        try:
            # 定义高风险端口列表
            high_risk_ports = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                80: "HTTP",
                110: "POP3",
                135: "RPC",
                137: "NetBIOS",
                138: "NetBIOS",
                139: "NetBIOS",
                443: "HTTPS",
                445: "SMB",
                3306: "MySQL",
                3389: "RDP",
                5900: "VNC",
                8080: "HTTP代理",
                8443: "HTTPS代理",
            }

            # 获取所有网络连接
            connections = psutil.net_connections(kind="inet")

            # 检查开放的高风险端口
            for conn in connections:
                if conn.status == "LISTEN" and conn.laddr.port in high_risk_ports:
                    open_high_risk_ports.append(
                        {
                            "port": conn.laddr.port,
                            "service": high_risk_ports[conn.laddr.port],
                            "address": conn.laddr.ip,
                        }
                    )

            if open_high_risk_ports:
                self.results["high_risk_ports"] = {
                    "status": "risk",
                    "level": "medium",
                    "message": f"检测到{len(open_high_risk_ports)}个高风险开放端口",
                    "details": open_high_risk_ports,
                    "suggestion": "关闭不必要的高风险端口，或使用防火墙限制访问",
                }
            else:
                self.results["high_risk_ports"] = {
                    "status": "normal",
                    "message": "未检测到高风险开放端口",
                }
        except Exception as e:
            self.results["high_risk_ports"] = {
                "status": "error",
                "message": f"高危端口检查失败: {str(e)}",
            }

    def check_firewall_status(self):
        """检查防火墙是否开启"""
        os_type = platform.system().lower()

        try:
            if os_type == "linux":
                # 检查Linux系统的防火墙状态
                cmd = "systemctl is-active firewalld"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                if "active" in result.stdout:
                    self.results["firewall"] = {
                        "status": "normal",
                        "message": "防火墙(firewalld)已启用",
                    }
                else:
                    # 尝试检查ufw
                    cmd = "sudo ufw status"
                    result = subprocess.run(
                        cmd, shell=True, capture_output=True, text=True
                    )

                    if "Status: active" in result.stdout:
                        self.results["firewall"] = {
                            "status": "normal",
                            "message": "防火墙(ufw)已启用",
                        }
                    else:
                        self.results["firewall"] = {
                            "status": "risk",
                            "level": "high",
                            "message": "未检测到防火墙已启用",
                            "suggestion": "建议启用系统防火墙以增强安全性",
                        }
            elif os_type == "windows":
                # 检查Windows系统的防火墙状态
                cmd = "netsh advfirewall show allprofiles"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                profiles = ["Domain Profile", "Private Profile", "Public Profile"]
                enabled_profiles = []

                for profile in profiles:
                    if (
                        profile in result.stdout
                        and "State" in result.stdout
                        and "ON" in result.stdout
                    ):
                        enabled_profiles.append(profile)

                if enabled_profiles:
                    self.results["firewall"] = {
                        "status": "normal",
                        "message": f"Windows防火墙已启用: {', '.join(enabled_profiles)}",
                    }
                else:
                    self.results["firewall"] = {
                        "status": "risk",
                        "level": "high",
                        "message": "Windows防火墙未启用",
                        "suggestion": "建议启用Windows防火墙以增强安全性",
                    }
            else:
                self.results["firewall"] = {
                    "status": "unknown",
                    "message": f"不支持的操作系统: {platform.system()}",
                }
        except Exception as e:
            self.results["firewall"] = {
                "status": "error",
                "message": f"防火墙检查失败: {str(e)}",
            }

    def check_system_resources(self):
        """检查CPU和内存使用率"""
        try:
            # 获取CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)

            # 获取内存使用率
            memory = psutil.virtual_memory()
            memory_percent = memory.percent

            # 检查CPU使用率
            cpu_status = "normal"
            cpu_level = None
            cpu_message = f"CPU使用率: {cpu_percent}%"
            cpu_suggestion = None

            if cpu_percent > 90:
                cpu_status = "risk"
                cpu_level = "high"
                cpu_message = f"CPU使用率过高: {cpu_percent}%"
                cpu_suggestion = "关闭不必要的程序或进程，释放CPU资源"
            elif cpu_percent > 75:
                cpu_status = "risk"
                cpu_level = "medium"
                cpu_message = f"CPU使用率较高: {cpu_percent}%"
                cpu_suggestion = "考虑关闭一些不必要的程序或进程"

            self.results["cpu_usage"] = {
                "status": cpu_status,
                "level": cpu_level,
                "message": cpu_message,
                "suggestion": cpu_suggestion,
            }

            # 检查内存使用率
            memory_status = "normal"
            memory_level = None
            memory_message = f"内存使用率: {memory_percent}%"
            memory_suggestion = None

            if memory_percent > 90:
                memory_status = "risk"
                memory_level = "high"
                memory_message = f"内存使用率过高: {memory_percent}%"
                memory_suggestion = "关闭不必要的程序或增加物理内存"
            elif memory_percent > 75:
                memory_status = "risk"
                memory_level = "medium"
                memory_message = f"内存使用率较高: {memory_percent}%"
                memory_suggestion = "考虑关闭一些不必要的程序"

            self.results["memory_usage"] = {
                "status": memory_status,
                "level": memory_level,
                "message": memory_message,
                "suggestion": memory_suggestion,
            }
        except Exception as e:
            self.results["system_resources"] = {
                "status": "error",
                "message": f"系统资源检查失败: {str(e)}",
            }

    def check_disk_health(self):
        """检查磁盘空间健康状况"""
        try:
            # 获取所有磁盘分区
            partitions = psutil.disk_partitions()

            disk_issues = []

            for partition in partitions:
                try:
                    # 跳过不可用的分区
                    if not os.path.ismount(partition.mountpoint):
                        continue

                    # 获取分区使用情况
                    usage = psutil.disk_usage(partition.mountpoint)

                    # 检查空间使用率
                    if usage.percent > 90:
                        disk_issues.append(
                            {
                                "partition": partition.mountpoint,
                                "total": f"{usage.total / (1024 ** 3):.2f} GB",
                                "used": f"{usage.used / (1024 ** 3):.2f} GB",
                                "free": f"{usage.free / (1024 ** 3):.2f} GB",
                                "percent": f"{usage.percent}%",
                                "issue": "空间使用率过高",
                            }
                        )
                    elif usage.percent > 80:
                        disk_issues.append(
                            {
                                "partition": partition.mountpoint,
                                "total": f"{usage.total / (1024 ** 3):.2f} GB",
                                "used": f"{usage.used / (1024 ** 3):.2f} GB",
                                "free": f"{usage.free / (1024 ** 3):.2f} GB",
                                "percent": f"{usage.percent}%",
                                "issue": "空间使用率较高",
                            }
                        )
                except Exception as e:
                    disk_issues.append(
                        {
                            "partition": partition.mountpoint,
                            "issue": f"检查失败: {str(e)}",
                        }
                    )

            if disk_issues:
                self.results["disk_health"] = {
                    "status": "risk",
                    "level": "medium",
                    "message": f"检测到{len(disk_issues)}个磁盘问题",
                    "details": disk_issues,
                    "suggestion": "清理磁盘空间或增加存储设备",
                }
            else:
                self.results["disk_health"] = {
                    "status": "normal",
                    "message": "所有磁盘分区空间充足",
                }
        except Exception as e:
            self.results["disk_health"] = {
                "status": "error",
                "message": f"磁盘健康检查失败: {str(e)}",
            }

    def generate_report(self):
        """生成风险报告"""
        # 统计风险数量
        risk_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # 准备探测结果列表
        detection_results = []

        # 处理每个检测项的结果
        for check_name, result in self.results.items():
            # 转换风险等级为中文
            status = result.get("status")
            level = result.get("level", "low")  # 默认值改为 low

            if status == "risk":
                risk_level_zh = self.risk_levels.get(level, level)
            elif status == "normal":
                risk_level_zh = "低风险"
            else:
                risk_level_zh = "未知"

            # 构建探测结果项
            detection_item = {
                "探测项目": check_name,
                "风险等级": risk_level_zh,
                "详情": result.get("message", ""),
                "建议": result.get("suggestion", ""),
            }

            # 添加详情信息
            if "details" in result:
                detection_item["详情"] += f" ({len(result['details'])}个问题)"

            # 统计风险
            if result.get("status") == "risk":
                risk_count[level] += 1

            detection_results.append(detection_item)

        # 计算总风险
        total_risks = sum(risk_count.values())

        self.mac_address = ":".join(
            [
                "{:02x}".format((uuid.getnode() >> elements) & 0xFF)
                for elements in range(0, 2 * 6, 2)
            ][::-1]
        )

        # 生成报告
        report = {
            "host_info": {
                "hostname": socket.gethostname(),
                "mac_address": self.mac_address,
                "os": platform.system(),
                "os_version": platform.version(),
                "ip_address": socket.gethostbyname(socket.gethostname()),
                "report_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "risk_summary": {
                "total_risks": total_risks,
                "critical": risk_count["critical"],
                "high": risk_count["high"],
                "medium": risk_count["medium"],
                "low": risk_count["low"],
            },
            "detection_results": detection_results,
        }

        return report

    def print_report(self):
        """打印风险报告"""
        report = self.generate_report()
        print("\n" + "=" * 50)
        print("个人主机风险探测报告")
        print("=" * 50)

        # 打印JSON格式的探测结果

        detection_json = json.dumps(
            report["detection_results"], ensure_ascii=False, indent=2
        )
        print(detection_json)


def main():
    """主函数"""
    print("开始进行个人主机风险探测...")

    # 创建风险检测器
    detector = HostRiskDetector()

    # 执行风险检测
    detector.detect_all_risks()

    # 打印报告
    detector.print_report()


if __name__ == "__main__":
    main()
