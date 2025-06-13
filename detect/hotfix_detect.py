import wmi
import pythoncom
import json
import datetime
import platform

def hotfix_detect(data):
    """
    补丁检测函数
    :param data: 包含主机信息的数据字典
    :return: JSON格式的检测结果
    """
    print("开始补丁安全发现......")
    result = {
        "type": "hotfix",
        "status": "success",
        "data": []
    }

    try:
        if platform.system() == "Windows":
            # 初始化COM
            pythoncom.CoInitialize()
            
            try:
                # 创建WMI客户端
                c = wmi.WMI()
                
                # 获取补丁信息
                hotfixes = c.Win32_QuickFixEngineering()
                
                # 组装补丁信息
                for hotfix in hotfixes:
                    patch_info = {
                        'id': hotfix.HotFixID,
                        'description': hotfix.Description or '',
                        'installedDate': str(hotfix.InstalledOn or ''),
                        'caption': hotfix.Caption or '',
                        'status': 'Installed'
                    }
                    result["data"].append(patch_info)
                    
            finally:
                # 确保COM被正确释放
                pythoncom.CoUninitialize()
                
        elif platform.system() == "Linux":
            # 对于Linux系统，检查已安装的更新
            import subprocess
            
            if subprocess.run(["which", "apt"], stdout=subprocess.PIPE).returncode == 0:
                # Debian/Ubuntu
                process = subprocess.run(["apt", "list", "--installed"], capture_output=True, text=True)
                updates = process.stdout.split('\n')
                for update in updates[1:]:  # 跳过第一行
                    if update.strip():
                        parts = update.split()
                        if len(parts) >= 2:
                            patch_info = {
                                'id': parts[0],
                                'description': f'Version: {parts[1]}',
                                'installedDate': '',
                                'caption': 'APT Package',
                                'status': 'Installed'
                            }
                            result["data"].append(patch_info)
                            
            elif subprocess.run(["which", "yum"], stdout=subprocess.PIPE).returncode == 0:
                # CentOS/RHEL
                process = subprocess.run(["yum", "list", "installed"], capture_output=True, text=True)
                updates = process.stdout.split('\n')
                for update in updates:
                    if update.strip() and not update.startswith(('Loaded:', 'Installed Packages')):
                        parts = update.split()
                        if len(parts) >= 2:
                            patch_info = {
                                'id': parts[0],
                                'description': f'Version: {parts[1]}',
                                'installedDate': '',
                                'caption': 'YUM Package',
                                'status': 'Installed'
                            }
                            result["data"].append(patch_info)
        else:
            result["status"] = "error"
            result["message"] = f"不支持的操作系统: {platform.system()}"
            
    except Exception as e:
        result["status"] = "error"
        result["message"] = str(e)
        print(f"补丁检测出错: {e}")
    
    print("补丁检测完成!")
    print("检测到的补丁信息：")
    for patch in result["data"]:
        print(f"补丁ID: {patch['id']}")
        print(f"描述: {patch['description']}")
        print(f"安装日期: {patch['installedDate']}")
        print("------------------------")
    
    return json.dumps(result)
