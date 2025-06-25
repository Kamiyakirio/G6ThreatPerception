import configparser
import datetime
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from baseline.baseline_detect import powershell_command
from system.pc_information import PcInfo
from utils.naming_convert import underscore_to_camelcase

file_path = "config.cfg"  # 配置文件路径
log_file_path = "output.txt"


def get_section_fields(file_path, sections_and_fields):
    """
    从配置文件中提取特定 section 的特定字段

    :param file_path: 配置文件路径
    :param sections_and_fields: 包含 section 和对应字段的字典
    :return: 提取的字段和值
    """
    config = configparser.ConfigParser()
    config.read(file_path, encoding="utf-16")  # 指定编码格式为 UTF-16

    result = {}

    for section, fields in sections_and_fields.items():
        if config.has_section(section):
            result[section] = {}
            for field in fields:
                if config.has_option(section, field):
                    result[section][field] = config.get(section, field)
                else:
                    print(f"字段 '{field}' 不存在于 section '{section}' 中。")
        else:
            print(f"Section '{section}' 不存在。")

    return result


# 整理数据
def get_baseline_cfg():
    baseline = {}
    sections_and_fields = {
        "System Access": [
            "MinimumPasswordAge",
            "MaximumPasswordAge",
            "MinimumPasswordLength",
            "PasswordComplexity",
            "PasswordHistorySize",
            "LockoutBadCount",
            "RequireLogonToChangePassword",
            "ForceLogoffWhenHourExpire",
            "NewAdministratorName",
            "NewGuestName",
            "ClearTextPassword",
            "LSAAnonymousNameLookup",
            "EnableAdminAccount",
            "EnableGuestAccount",
        ],
        "Event Audit": [
            "AuditSystemEvents",
            "AuditLogonEvents",
            "AuditObjectAccess",
            "AuditPrivilegeUse",
            "AuditPolicyChange",
            "AuditAccountManage",
            "AuditProcessTracking",
            "AuditDSAccess",
            "AuditAccountLogon",
        ],
        "Privilege Rights": [
            "SeProfileSingleProcessPrivilege",
            "SeRemoteShutdownPrivilege",
            "SeShutdownPrivilege",
        ],
    }
    result = get_section_fields(file_path, sections_and_fields)
    baseline["system_access"] = result["System Access"]
    baseline["event_audit"] = result["Event Audit"]
    baseline["privilege_rights"] = result["Privilege Rights"]
    return baseline


def get_baseline_txt():
    """
    解析文本文件中的 SysSecurityOptionPolicy 字段并提取整行内容
    :param file_path: 日志文件路径
    :return: 包含字段和整行内容的字典
    """
    result = {}
    data = {}
    # 匹配以 SysSecurityOptionPolicy:: 开头的行
    pattern = r"(SysSecurityOptionPolicy::[^=]+)(.+)$"

    with open(log_file_path, "r", encoding="utf-8") as file:
        for line in file:
            match = re.search(pattern, line.strip())
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()
                result[key] = value
    # 获取值中的第一个数字为新值
    data["NoLMHash"] = re.search(
        r"\d+", result["SysSecurityOptionPolicy::NoLMHash"]
    ).group()
    data["LimitBlankPasswordUse"] = re.search(
        r"\d+", result["SysSecurityOptionPolicy::LimitBlankPasswordUse"]
    ).group()
    data["RestrictAnonymous"] = re.search(
        r"\d+", result["SysSecurityOptionPolicy::RestrictAnonymous"]
    ).group()
    data["DontDisplayLastUserName"] = re.search(
        r"\d+", result["SysSecurityOptionPolicy::DontDisplayLastUserName"]
    ).group()
    data["EnablePlainTextPassword"] = re.search(
        r"\d+", result["SysSecurityOptionPolicy::EnablePlainTextPassword"]
    ).group()
    data["ClearPageFileAtShutdown"] = re.search(
        r"\d+", result["SysSecurityOptionPolicy::ClearPageFileAtShutdown"]
    ).group()
    return data


def get_baseline():
    """
    获取基线数据
    :return: 基线数据
    """
    # 运行脚本
    powershell_command()
    data = get_baseline_cfg()
    data["system_security_option"] = get_baseline_txt()

    return data


def baseline_detect(data):
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
        return_data["info"] = {
            underscore_to_camelcase(k): v for k, v in basic_info.items()
        }

        if data["baseline_task"]:
            t = thread_pool.submit(get_baseline)
            threads.append(t)

        for i in as_completed(threads):
            result = i.result()
            # 组装完整的 JSON 结构
            return_data["data"].append({"type": "baseline", "data": result})

        return_data["info"]["time"] = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        # print(return_data)
        print("Detect ended!")

        # 🔥 最终返回为字符串
        return json.dumps(return_data, ensure_ascii=False)


if __name__ == "__main__":
    test_data = {
        "host_name": "localhost",
        "mac_address": "f5:d4:52:4a:2b:af",
        "id": "1",
        "baseline_task": True,
    }
    print(baseline_detect(test_data))
