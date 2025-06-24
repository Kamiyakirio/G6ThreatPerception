import datetime
import html
import json
import os
from evtx import PyEvtxParser
import re
from xml.dom import minidom
from difflib import SequenceMatcher


log_paths = {
    "security": r"C:\Windows\System32\winevt\Logs\Security.evtx",
    "system": r"C:\Windows\System32\winevt\Logs\System.evtx",
}
# 定义要查询的事件ID
event_dicts = {
    "security": [4624, 4625, 4634, 4647, 4720, 4722, 4723, 4724, 4728, 4738, 4726],
    "system": [1074, 6005, 6006, 6008, 6009, 6013, 7036, 7040, 7045, 1102],
}
risk_rules = {
    "high_risk_events": {
        4720: {"desc": "创建用户账户", "level": 3},  # 创建用户
        4726: {"desc": "删除用户账户", "level": 3},  # 删除用户
        4728: {"desc": "将成员添加到安全组", "level": 3},  # 添加组成员
    },
    "medium_risk_events": {
        4625: {"desc": "用户登录失败", "level": 2},  # 失败登录
        4722: {"desc": "启用用户账户", "level": 2},  # 启用用户
        4723: {"desc": "尝试更改账户密码", "level": 2},  # 尝试更改密码
        4724: {"desc": "尝试重置账户密码", "level": 2},  # 尝试重置密码
    },
    "low_risk_events": {
        4738: {"desc": "用户账户已更改", "level": 1},  # 用户账户更改
    },
    "no_risk_events": {
        4624: {"desc": "用户成功登录", "level": 0},  # 成功登录
        4634: {"desc": "用户注销", "level": 0},  # 用户注销
        4647: {"desc": "用户启动了自己的账户注销", "level": 0},  # 主动注销
        1074: {"desc": "系统已关闭", "level": 0},
        6005: {"desc": "事件日志服务已启动", "level": 0},
        6006: {"desc": "事件日志服务已停止", "level": 0},
        6008: {"desc": "系统在未正常关闭的情况下重新启动", "level": 0},
        6009: {"desc": "已识别系统", "level": 0},
        6013: {"desc": "系统正常运行时间", "level": 0},
        7036: {"desc": "服务已启动或停止", "level": 0},
        7040: {"desc": "服务启动类型已更改", "level": 0},
        7045: {"desc": "已安装新服务", "level": 0},
        1102: {"desc": "审核日志已清除", "level": 0},
    },
    "dangerous_usernames": [
        "admin",
        "administrator",
        "root",
        "test",
        "guest",
        "backup",
        "default",
        "temp",
        "support",
        "audit",
    ],
    "abnormal_hours": [0, 1, 2, 3, 4, 5, 6, 22, 23],  # 定义非正常时段（22:00-06:00）
}


def get_log_info(event_path, **kwargs):
    """
    过滤指定条件的日志
    :param event_path: 日志文件路径
    :param kwargs: 过滤条件，支持event_id, start_time, end_time
    :return: 符合条件的日志列表
    """
    # 解析参数
    event_id_param = kwargs.get("event_id")
    start_time = kwargs.get("start_time")
    end_time = kwargs.get("end_time")

    # 创建Evtx解析器
    parser = PyEvtxParser(event_path)
    event_id_pattern = re.compile(r"<EventID>(\d+)</EventID>")
    channel_pattern = re.compile(r"<Channel>(.*?)</Channel>")

    # 存储结果的列表
    event_list = []

    # 遍历日志条目
    for record in parser.records():
        xml_data = record["data"]

        # 提取EventID
        event_id_match = re.search(event_id_pattern, xml_data)
        if not event_id_match:
            continue
        event_id = int(event_id_match.group(1))

        # 提取Channel
        channel_match = re.search(channel_pattern, xml_data)
        channel = channel_match.group(1) if channel_match else "Unknown"

        # 时间范围过滤
        if start_time is not None and record["timestamp"] < start_time:
            continue
        if end_time is not None and record["timestamp"] > end_time:
            continue

        # 事件ID过滤
        if event_id_param is not None and event_id != event_id_param:
            continue

        # 解析XML数据节点
        event_data = {
            "event_id": event_id,
            "timestamp": record["timestamp"],
            "channel": channel,
        }

        try:
            xml_doc = minidom.parseString(xml_data)
            for data_node in xml_doc.getElementsByTagName("Data"):
                try:
                    name = data_node.getAttribute("Name")
                    value = (
                        html.unescape(data_node.childNodes[0].data)
                        if data_node.hasChildNodes()
                        else ""
                    )
                    event_data[name] = value
                except Exception:
                    continue
        except Exception:
            pass

        event_list.append(event_data)

    return event_list


def log_detect(start_time, end_time):
    """
    收集指定时间范围内的所有日志事件
    :return: 包含所有日志的字典
    """
    print(f"时间范围: {start_time} - {end_time}")

    # 存储所有日志的结果列表
    all_logs = []

    # 遍历日志类型（security, system）
    for log_type, event_ids in event_dicts.items():
        log_path = log_paths.get(log_type)
        if not log_path or not os.path.exists(log_path):
            print(f"警告: {log_type}日志路径不存在 - {log_path}")
            continue

        print(f"\n正在处理{log_type}日志，路径: {log_path}")
        print(f"查询事件ID: {event_ids}")

        # 按事件ID查询并存储结果
        for event_id in event_ids:
            try:
                print(f"  查询事件ID {event_id}...")
                event_list = get_log_info(
                    log_path,
                    event_id=event_id,
                    start_time=start_time,
                    end_time=end_time,
                )
                # 只对低风险事件进行去重
                if event_id in risk_rules["low_risk_events"]:
                    event_list = deduplicate_low_risk(event_list)
                # 将所有事件添加到结果列表中
                all_logs.extend(event_list)
                print(f"  找到{len(event_list)}条记录")
            except Exception as e:
                print(f"  查询事件ID {event_id}时出错: {str(e)}")

    return all_logs


# 判断两个字符串的相似度
def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()


# 去重逻辑，对中低风险的事件进行去重，
import random


def deduplicate_low_risk(event_list, threshold=0.3, keep_probability=0.25):
    """
    去除约 70% 的重复数据，保留 30% 的重复数据。

    :param event_list: 日志列表
    :param threshold: 相似度阈值，低于该值认为是"不重复"
    :param keep_probability: 保留重复项的概率（用于模拟保留 30% 的重复数据）
    :return: 去重后的日志列表
    """
    seen_data = []
    result_list = []
    id_list = []
    for event in event_list:
        event_id = event.get("event_id")
        if event_id not in id_list:
            result_list.append(event)
            id_list.append(event_id)
            continue

        data = event.get("Data", "")  # 获取关键字段内容

        is_duplicate = False
        for existing_data in seen_data:
            similarity = similar(data, existing_data)
            if similarity >= threshold:
                is_duplicate = True
                # 按概率决定是否保留
                if random.random() < keep_probability:
                    result_list.append(event)
                break

        if not is_duplicate:
            seen_data.append(data)
            result_list.append(event)

    return result_list


def analyze_risk_grade(all_logs):
    analysis_results = []
    for event in all_logs:
        risk_details = []
        event_id = event.get("event_id")
        
        # 判断事件类型和基础风险等级
        if event_id in risk_rules["low_risk_events"]:
            base_risk = risk_rules["low_risk_events"][event_id]["level"]
            risk_desc_base = risk_rules["low_risk_events"][event_id]["desc"]
        elif event_id in risk_rules["medium_risk_events"]:
            base_risk = risk_rules["medium_risk_events"][event_id]["level"]
            risk_desc_base = risk_rules["medium_risk_events"][event_id]["desc"]
        elif event_id in risk_rules["high_risk_events"]:
            base_risk = risk_rules["high_risk_events"][event_id]["level"]
            risk_desc_base = risk_rules["high_risk_events"][event_id]["desc"]
        elif event_id in risk_rules["no_risk_events"]:
            base_risk = risk_rules["no_risk_events"][event_id]["level"]
            risk_desc_base = risk_rules["no_risk_events"][event_id]["desc"]
        else:
            base_risk = 0
            risk_desc_base = "无风险"
        risk_details.append(risk_desc_base)
        timestamp = event.get("timestamp", "")
        username = event.get("TargetUserName") or event.get("SubjectUserName", "")
        channel = event.get("channel", "Unknown")

        # 初始化风险级别
        risk_level = base_risk
        
        # 特殊处理：用户登录成功事件(4624)
        if event_id == 4624:
            # 如果是危险用户名，则提升为高风险
            if username and username.lower() in [name.lower() for name in risk_rules["dangerous_usernames"]]:
                risk_level = 3
                risk_details.append(f"使用危险用户名登录: {username}")
        # 检查是否是危险用户名（除登录成功事件外的其他事件）
        elif username and username.lower() in [name.lower() for name in risk_rules["dangerous_usernames"]]:
            risk_level = max(risk_level, 3)  # 危险用户名提升为高风险
            risk_details.append(f"使用危险用户名: {username}")

        # 检查是否在非正常时段
        if timestamp:
            try:
                event_time = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                if event_time.hour in risk_rules["abnormal_hours"]:
                    risk_level = max(risk_level, 2)  # 非正常时段提升为中风险
                    risk_details.append(f"在非正常时段登录: {event_time.hour}:00")
            except ValueError:
                pass

        # 构建分析结果
        risk_details = str(risk_details).replace("[", "").replace("]", "").replace("'", "")
        result_entry = {
            "event_id": event_id,
            "risk_level": risk_level,
            "timestamp": timestamp,
            "risk_desc": risk_details,
            "channel": channel,
            "event_data": event,
        }
        analysis_results.append(result_entry)

    return analysis_results


def log_analysis_result_send(data):
    start_time = data.get("start_time")
    end_time = data.get("end_time")
    event_list = log_detect(start_time, end_time)
    return analyze_risk_grade(event_list), start_time, end_time


if __name__ == "__main__":
    # 打印出今天的日志检测结果
    data = log_detect(
        start_time=datetime.datetime.now().strftime("%Y-%m-%d 00:00:00"),
        end_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    # print(analyze_risk_grade(data))
