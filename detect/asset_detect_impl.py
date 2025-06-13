import os
import wmi
import pythoncom
import json
import nmap
import winreg


from utils.naming_convert import underscore_to_camelcase


def detect_account():
    print("Starting detecting users on the computer...")

    pythoncom.CoInitialize()
    c = wmi.WMI()
    account_list = []

    # 获取所有用户
    for user in c.Win32_UserAccount():
        user_dict = {
            "name": user.Name,
            "full_name": user.FullName,
            "sid": user.SID,
            "sid_type": user.SIDType,
            "status": user.Status,
            "disabled": user.Disabled,
            "lockout": user.Lockout,
            "password_changeable": user.PasswordChangeable,
            "password_expires": user.PasswordExpires,
            "password_required": user.PasswordRequired,
        }
        account_list.append(user_dict)
    # 去初始化
    pythoncom.CoUninitialize()

    # 转换成JSON字符串
    account_data = json.dumps({"type": "account", "data": account_list})

    print("User detection ended!")
    return {"type": "account", "data": account_list}


def detect_app():
    # 从注册表获取软件信息
    print("Starting detecting installed softwares...")
    registry_key = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    )
    software_list = []
    # 获取软件数量
    number = winreg.QueryInfoKey(registry_key)[0]
    for i in range(number):
        try:
            sub_key_name = winreg.EnumKey(registry_key, i)
            sub_key = winreg.OpenKey(registry_key, sub_key_name)

            software = {}
            try:
                software["display_name"] = winreg.QueryValueEx(sub_key, "DisplayName")[
                    0
                ]
                software["install_location"] = winreg.QueryValueEx(
                    sub_key, "InstallLocation"
                )[0]
                software["uninstall_string"] = winreg.QueryValueEx(
                    sub_key, "UninstallString"
                )[0]
                software_list.append(software)
            except WindowsError:
                continue
        except WindowsError:
            break
    # 转换成JSON字符串
    app_data = json.dumps({"type": "app", "data": software_list})

    print("Software detecting ended!")
    return {"type": "app", "data": software_list}


def detect_process():
    print("Starting detecting running process...")
    pythoncom.CoInitialize()
    c = wmi.WMI()
    process_list = []
    for process in c.Win32_Process():
        process_info = {
            # 'mac': self.__data['mac'],
            "pid": process.ProcessId,
            "ppid": process.ParentProcessId,
            "name": process.Name,
            "cmd": process.CommandLine,
            "priority": process.Priority,
            "description": process.Description,
        }
        process_list.append(process_info)
    # 去初始化
    pythoncom.CoUninitialize()
    # 转换成JSON
    process_data = json.dumps({"type": "process", "data": process_list})
    # 发送到队列
    # self.__mq_produce_process_data(process_data)
    print("Process detecting ended!")
    return {"type": "process", "data": process_list}


def detect_service():
    """
    探测服务
    :return:
    """
    print("Starting port scans...")
    # 创建一个扫描仪对象
    nm = nmap.PortScanner()
    # 扫描目标主机
    nm.scan(hosts="127.0.0.1", arguments="-sSV -Pn -p 1-32767 -T4")  # 指定扫描端口范围
    # 获取扫描结果
    state = nm.all_hosts()
    # 装最终结果的
    res_list = []
    if state:
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
            for port in lport:
                # 接收nmap扫描结果
                nmap_res = {
                    #'mac': self.__data['mac'],
                    "protocol": proto,
                    "port": port,
                    "state": nm[host][proto][port]["state"],
                    "name": nm[host][proto][port]["name"],
                    "product": nm[host][proto][port]["product"],
                    "version": nm[host][proto][port]["version"],
                    "extrainfo": nm[host][proto][port]["extrainfo"],
                }
                res_list.append(nmap_res)
    # 转换成JSON字符串
    res_json = json.dumps({"type": "service", "data": res_list})
    # 发送到队列
    # self.__mq.produce_service_data(res_json)
    print("Port scans ended!")
    return {"type": "service", "data": res_list}


if __name__ == "__main__":

    detect_service()
