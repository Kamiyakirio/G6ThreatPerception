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
    print(f"接收到的数据: {data}")
    result = []

    try:
        # 确保data是字典类型
        if isinstance(data, str):
            data = json.loads(data)

        mac_address = data["mac_address"]

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
                        "macAddress": mac_address,
                        "hotfixId": hotfix.HotFixID,
                    }
                    result.append(patch_info)

            finally:
                # 确保COM被正确释放
                pythoncom.CoUninitialize()

        elif platform.system() == "Linux":
            # 对于Linux系统，检查已安装的更新
            import subprocess

            if subprocess.run(["which", "apt"], stdout=subprocess.PIPE).returncode == 0:
                # Debian/Ubuntu
                process = subprocess.run(
                    ["apt", "list", "--installed"], capture_output=True, text=True
                )
                updates = process.stdout.split("\n")
                for update in updates[1:]:  # 跳过第一行
                    if update.strip():
                        parts = update.split()
                        if len(parts) >= 2:
                            patch_info = {
                                "macAddress": mac_address,
                                "hotfixId": parts[0],
                            }
                            result.append(patch_info)

            elif (
                subprocess.run(["which", "yum"], stdout=subprocess.PIPE).returncode == 0
            ):
                # CentOS/RHEL
                process = subprocess.run(
                    ["yum", "list", "installed"], capture_output=True, text=True
                )
                updates = process.stdout.split("\n")
                for update in updates:
                    if update.strip() and not update.startswith(
                        ("Loaded:", "Installed Packages")
                    ):
                        parts = update.split()
                        if len(parts) >= 2:
                            patch_info = {
                                "macAddress": mac_address,
                                "hotfixId": parts[0],
                            }
                            result.append(patch_info)
        else:
            print(f"不支持的操作系统: {platform.system()}")

    except Exception as e:
        print(f"补丁检测出错: {e}")
        import traceback

        traceback.print_exc()
        # 发生错误时返回空列表
        result = []

    print("补丁检测完成!")
    print(f"检测到 {len(result)} 个补丁")
    return json.dumps(result)
