import datetime
import json
import os
import subprocess
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor

from baseline.log_handler import baseline_detect
from system.pc_information import PcInfo
from utils.naming_convert import underscore_to_camelcase

external_config = {
        "MinimumPasswordAge": "1",
        "MaximumPasswordAge": "42",
        "MinimumPasswordLength": "14",
        "PasswordComplexity": "1",
        "PasswordHistorySize": "5",
        "LockoutBadCount": "5",
        # 审核策略
        "AuditSystemEvents": "3",
        "AuditLogonEvents": "3",
        "AuditObjectAccess": "3",
        "AuditPrivilegeUse": "3",
        "AuditPolicyChange": "3",
        "AuditAccountManage": "3",
        "AuditProcessTracking": "3",
        "AuditDSAccess": "3",
        "AuditAccountLogon": "3"
    }
# external_config = {
#         "MinimumPasswordAge": "0",
#         "MaximumPasswordAge": "42",
#         "MinimumPasswordLength": "0",
#         "PasswordComplexity": "0",
#         "PasswordHistorySize": "0",
#         "LockoutBadCount": "0",
#         # 审核策略
#         "AuditSystemEvents": "0",
#         "AuditLogonEvents": "0",
#         "AuditObjectAccess": "0",
#         "AuditPrivilegeUse": "0",
#         "AuditPolicyChange": "0",
#         "AuditAccountManage": "0",
#         "AuditProcessTracking": "0",
#         "AuditDSAccess": "0",
#         "AuditAccountLogon": "0"
#     }
def apply_account_policies(config):
    """
    根据传入的字典配置修改账号安全策略
    :param config: 字段与值的字典，例如：
                   {
                       "MinimumPasswordAge": "1",
                       "MaximumPasswordAge": "90",
                       ...
                   }
    """
    # 获取当前脚本所在目录
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # 固定路径：项目目录下的 baseline_policy 文件夹
    policy_dir = os.path.join(script_dir, "baseline_policy")
    os.makedirs(policy_dir, exist_ok=True)  # 如果不存在则创建

    # 文件路径定义
    inf_path = os.path.join(policy_dir, "security_config.inf")
    modified_inf_path = os.path.join(policy_dir, "security_config_modified.inf")
    sdb_path = os.path.join(policy_dir, "secedit.sdb")

    # Step 1: 导出当前安全策略
    print(f"导出安全策略到 {inf_path}...")
    subprocess.run(["secedit", "/export", "/cfg", inf_path, "/quiet"], check=True)

    # Step 2: 读取原始 INF 文件内容
    print("读取策略文件...")
    with open(inf_path, "r", encoding="utf-16-le", errors='ignore') as infile:
        lines = infile.readlines()

    # Step 3: 替换指定字段
    updated_lines = []
    for line in lines:
        key_in_line = line.split("=", 1)[0].strip()
        if key_in_line in config:
            print(f"修改策略项: {key_in_line} => {config[key_in_line]}")
            updated_lines.append(f"{key_in_line} = {config[key_in_line]}\n")
        else:
            updated_lines.append(line)

    # Step 4: 写入修改后的内容
    print(f"写入新策略文件到 {modified_inf_path}")
    with open(modified_inf_path, "w", encoding="utf-16-le", errors='ignore') as outfile:
        outfile.writelines(updated_lines)

    # Step 5: 应用新的安全策略
    print(f"正在应用策略，请稍等... 数据库路径: {sdb_path}")
    try:
        subprocess.run([
            "secedit",
            "/configure",
            "/db", sdb_path,
            "/cfg", modified_inf_path,
            "/quiet"
        ], check=True)
        print("所有账号策略已更新")
    except subprocess.CalledProcessError as e:
        print("策略应用失败")

def baseline_repair(data):
    threads = []
    thread_pool = ThreadPoolExecutor(16)
    return_data = {"data": []}
    basic_info = {
        "host_name": data["host_name"],
        "mac_address": data["mac_address"],
        "id": data["id"],
    }
    # 校验mac地址的合法性，如果不是本机的mac地址，则不执行命令，并返回空
    # 实时获取本机的mac地址，并与配置文件中的mac地址进行对比，如果相同，则返回数据，否则返回空
    info = PcInfo()
    localhost_mac_address = info.get_info_dict()["mac_address"]
    if localhost_mac_address != data["mac_address"]:
        return ""
    else:
        return_data["info"] = {underscore_to_camelcase(k): v for k, v in basic_info.items()}

        if data["baseline_reinforce"]:
            t = thread_pool.submit(apply_account_policies, external_config)
            threads.append(t)


        # 组装完整的 JSON 结构
        return_data["data"].append({
            "type": "baseline_repair",
            "data": 'success'
        })

        return_data["info"]["time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(return_data)
        print("Detect ended!")

        # 🔥 最终返回为字符串
        return json.dumps(return_data, ensure_ascii=False)

if __name__ == "__main__":
    # 示例字典输入（由外部传入）
    # data = {
    #     "MinimumPasswordAge": "1",
    #     "MaximumPasswordAge": "42",
    #     "MinimumPasswordLength": "14",
    #     "PasswordComplexity": "1",
    #     "PasswordHistorySize": "5",
    #     "LockoutBadCount": "5",
    #     # 审核策略
    #     "AuditSystemEvents": "3",
    #     "AuditLogonEvents": "3",
    #     "AuditObjectAccess": "3",
    #     "AuditPrivilegeUse": "3",
    #     "AuditPolicyChange": "3",
    #     "AuditAccountManage": "3",
    #     "AuditProcessTracking": "3",
    #     "AuditDSAccess": "3",
    #     "AuditAccountLogon": "3",
    #     "host_name": "localhost",
    #     "mac_address": "f5:d4:52:4a:2b:af",
    #     "id": "1",
    #     "baseline_reinforce": True
    # }
    data = {
        "MinimumPasswordAge": "0",
        "MaximumPasswordAge": "42",
        "MinimumPasswordLength": "0",
        "PasswordComplexity": "0",
        "PasswordHistorySize": "0",
        "LockoutBadCount": "0",
        # 审核策略
        "AuditSystemEvents": "0",
        "AuditLogonEvents": "0",
        "AuditObjectAccess": "0",
        "AuditPrivilegeUse": "0",
        "AuditPolicyChange": "0",
        "AuditAccountManage": "0",
        "AuditProcessTracking": "0",
        "AuditDSAccess": "0",
        "AuditAccountLogon": "0",
        "host_name": "localhost",
        "mac_address": "f5:d4:52:4a:2b:af",
        "id": "1",
        "baseline_reinforce": True
    }
    print(baseline_repair(data))

