import json
import datetime
import os
from evtx import PyEvtxParser
import re
import html
from xml.dom import minidom
from collections import Counter
from difflib import SequenceMatcher

DEFAULT_LOG_FILE = os.path.join("log_detect\log_out_file", "evtx_logs.json")
DEFAULT_RESULT_FILE = os.path.join("log_detect\log_out_file", "risk_analyzed_logs.json")


class LogAnalyzer:
    def __init__(self, log_file=DEFAULT_LOG_FILE, metadata=None):
        """初始化日志分析器"""
        self.log_file = log_file
        self.metadata = metadata or {}
        self.logs = {}
        self.analysis_results = []

        # 定义风险评估规则（使用数字风险等级）
        self.risk_rules = {
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
                4624: {"desc": "用户成功登录", "level": 1},  # 成功登录（默认低风险）
                4634: {"desc": "用户注销", "level": 1},  # 用户注销
                4647: {"desc": "用户启动了自己的账户注销", "level": 1},  # 主动注销
                4738: {"desc": "用户账户已更改", "level": 1},  # 用户账户更改
            },
            "system_events": {
                1074: {"desc": "系统已关闭", "level": 0},
                6005: {"desc": "事件日志服务已启动", "level": 0},
                6006: {"desc": "事件日志服务已停止", "level": 0},
                6008: {"desc": "系统在未正常关闭的情况下重新启动", "level": 0},
                6009: {"desc": "已识别系统", "level": 0},
                6013: {"desc": "系统正常运行时间", "level": 0},
                7036: {"desc": "服务已启动或停止", "level": 0},
                7040: {"desc": "服务启动类型已更改", "level": 0},
                7045: {"desc": "已安装新服务", "level": 0},
                1102: {"desc": "审核日志已清除", "level": 0}
            },
            "dangerous_usernames": [
                "admin", "administrator", "root", "test", "guest",
                "backup", "default", "temp", "support", "audit"
            ],
            "abnormal_hours": [0, 1, 2, 3, 4, 5, 6, 22, 23]  # 定义非正常时段（22:00-06:00）
        }

    def get_log_info(self, event_path, **kwargs):
        """
        过滤指定条件的日志
        :param event_path: 日志文件路径
        :param kwargs: 过滤条件，支持event_id, start_time, end_time
        :return: 符合条件的日志列表
        """
        # 解析参数
        event_id_param = kwargs.get('event_id')
        start_time = kwargs.get('start_time')
        end_time = kwargs.get('end_time')

        # 创建Evtx解析器
        parser = PyEvtxParser(event_path)
        event_id_pattern = re.compile(r'<EventID>(\d+)</EventID>')
        channel_pattern = re.compile(r'<Channel>(.*?)</Channel>')

        # 存储结果的列表
        event_list = []

        # 遍历日志条目
        for record in parser.records():
            xml_data = record['data']

            # 提取EventID
            event_id_match = re.search(event_id_pattern, xml_data)
            if not event_id_match:
                continue
            event_id = int(event_id_match.group(1))

            # 提取Channel
            channel_match = re.search(channel_pattern, xml_data)
            channel = channel_match.group(1) if channel_match else "Unknown"

            # 时间范围过滤
            if start_time is not None and record['timestamp'] < start_time:
                continue
            if end_time is not None and record['timestamp'] > end_time:
                continue

            # 事件ID过滤
            if event_id_param is not None and event_id != event_id_param:
                continue

            # 解析XML数据节点
            event_data = {
                'event_id': event_id,
                'timestamp': record['timestamp'],
                'channel': channel
            }

            try:
                xml_doc = minidom.parseString(xml_data)
                for data_node in xml_doc.getElementsByTagName('Data'):
                    try:
                        name = data_node.getAttribute('Name')
                        value = html.unescape(data_node.childNodes[0].data) if data_node.hasChildNodes() else ""
                        event_data[name] = value
                    except Exception:
                        continue
            except Exception:
                pass

            event_list.append(event_data)

        return event_list

    def log_detect(self, start_time, end_time):
        """
        日志检测并导出为JSON
        :return: 包含所有日志的字典
        """
        # 定义日志路径
        log_paths = {
            "security": r'C:\Windows\System32\winevt\Logs\Security.evtx',
            "system": r'C:\Windows\System32\winevt\Logs\System.evtx'
        }

        # 定义要查询的事件ID
        event_dicts = {
            "security": [4624, 4625, 4634, 4647, 4720, 4722, 4723, 4724, 4728, 4738, 4726],
            "system": [1074, 6005, 6006, 6008, 6009, 6013, 7036, 7040, 7045, 1102]
        }

        print(f"时间范围: {start_time} - {end_time}")

        # 存储所有日志的结果字典
        all_logs = {}

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
                    event_list = self.get_log_info(
                        log_path,
                        event_id=event_id,
                        start_time=start_time,
                        end_time=end_time
                    )

                    # 使用log_type/event_id作为键存储结果
                    key = f"{log_type}_{event_id}"
                    all_logs[key] = event_list

                    print(f"  找到{len(event_list)}条记录")
                except Exception as e:
                    print(f"  查询事件ID {event_id}时出错: {str(e)}")

        return all_logs

    def export_to_json(self, data, filename=DEFAULT_LOG_FILE):
        """
        将数据导出到JSON文件
        :param data: 要导出的数据
        :param filename: 输出文件名
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"\n成功导出到 {filename}")
        except Exception as e:
            print(f"导出到JSON时出错: {str(e)}")

    def load_logs(self):
        """加载日志数据"""
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                self.logs = json.load(f)
            print(f"成功加载 {len(self.logs)} 种类型的日志数据")
            return True
        except Exception as e:
            print(f"加载日志文件时出错: {str(e)}")
            return False

    def analyze_logs(self):
        """分析日志并评估风险"""
        if not self.logs:
            print("没有日志数据可供分析")
            return

        total_events = 0

        # 遍历所有类型的日志
        for event_type, events in self.logs.items():
            log_type, event_id = event_type.split('_', 1)
            event_id = int(event_id)

            # 确定事件的基础风险级别
            if event_id in self.risk_rules["high_risk_events"]:
                base_risk = self.risk_rules["high_risk_events"][event_id]["level"]
                risk_desc = self.risk_rules["high_risk_events"][event_id]["desc"]
            elif event_id in self.risk_rules["medium_risk_events"]:
                base_risk = self.risk_rules["medium_risk_events"][event_id]["level"]
                risk_desc = self.risk_rules["medium_risk_events"][event_id]["desc"]
            elif event_id in self.risk_rules["low_risk_events"]:
                base_risk = self.risk_rules["low_risk_events"][event_id]["level"]
                risk_desc = self.risk_rules["low_risk_events"][event_id]["desc"]
            elif event_id in self.risk_rules["system_events"]:
                base_risk = self.risk_rules["system_events"][event_id]["level"]
                risk_desc = self.risk_rules["system_events"][event_id]["desc"]
            else:
                base_risk = 0  # 未知事件设为无风险
                risk_desc = "未知事件类型"

            # 分析每条具体日志
            for event in events:
                total_events += 1
                timestamp = event.get('timestamp', '')
                username = event.get('TargetUserName') or event.get('SubjectUserName', '')
                ip_address = event.get('IpAddress', 'Unknown')
                logon_type = event.get('LogonType', 'Unknown')
                channel = event.get('channel', 'Unknown')

                # 初始化风险级别和描述
                risk_level = base_risk
                risk_details = []

                # 特殊处理：用户登录成功事件(4624)
                if event_id == 4624:
                    # 如果是危险用户名，则提升为高风险
                    if username.lower() in [name.lower() for name in self.risk_rules["dangerous_usernames"]]:
                        risk_level = 3
                        risk_details.append(f"使用危险用户名登录: {username}")
                    else:
                        # 非危险用户名登录设为低风险（已在规则中设置）
                        pass

                # 检查是否是危险用户名（除登录成功事件外的其他事件）
                elif username.lower() in [name.lower() for name in self.risk_rules["dangerous_usernames"]]:
                    risk_level = max(risk_level, 3)  # 危险用户名提升为高风险
                    risk_details.append(f"使用危险用户名: {username}")

                # 检查是否在非正常时段
                if timestamp:
                    try:
                        event_time = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                        if event_time.hour in self.risk_rules["abnormal_hours"]:
                            risk_level = max(risk_level, 2)  # 非正常时段提升为中风险
                            risk_details.append(f"在非正常时段登录: {event_time.hour}:00")
                    except ValueError:
                        pass

                # 合并风险描述
                if risk_details:
                    risk_desc += " - " + ", ".join(risk_details)

                # 构建分析结果
                result_entry = {
                    "event_id": event_id,
                    "risk_level": risk_level,
                    "timestamp": timestamp,
                    "risk_desc": risk_desc,
                    "channel": channel,
                    "event_data": event
                }

                self.analysis_results.append(result_entry)

        print(f"分析完成，共处理 {total_events} 条日志记录")

    def similar(self, a, b):
        """计算两个字符串的相似度"""
        return SequenceMatcher(None, a, b).ratio()

    def deduplicate_low_risk(self, threshold=0.9):
        """对低风险和无风险事件进行相似度去重"""
        if not self.analysis_results:
            return

        high_risk = []
        low_risk = []

        # 分离高风险和低/无风险事件
        for event in self.analysis_results:
            if event["risk_level"] >= 2:  # 中高风险直接保留
                high_risk.append(event)
            else:
                low_risk.append(event)

        print(f"原始低/无风险事件数量: {len(low_risk)}")

        # 对低/无风险事件进行去重
        deduplicated_low = []
        for event in low_risk:
            # 提取关键信息用于比较
            key_info = f"{event['event_id']}_{event['risk_desc']}_{event['timestamp'][:10]}"

            # 检查是否与已保留的事件相似
            is_duplicate = False
            for saved_event in deduplicated_low:
                saved_key = f"{saved_event['event_id']}_{saved_event['risk_desc']}_{saved_event['timestamp'][:10]}"
                if self.similar(key_info, saved_key) > threshold:
                    is_duplicate = True
                    break

            if not is_duplicate:
                deduplicated_low.append(event)

        print(f"去重后低/无风险事件数量: {len(deduplicated_low)}")

        # 合并结果
        self.analysis_results = high_risk + deduplicated_low
        print(f"最终保留事件总数: {len(self.analysis_results)}")

    def deduplicate_medium_high_risk(self, threshold=0.95):
        """对中高风险日志进行相似度去重"""
        if not self.analysis_results:
            return

        filtered_results = []

        # 按风险级别分组处理
        risk_groups = {0: [], 1: [], 2: [], 3: []}
        for event in self.analysis_results:
            risk_groups[event["risk_level"]].append(event)

        # 对低风险和无风险事件，使用原有去重逻辑
        low_risk_events = risk_groups[0] + risk_groups[1]
        deduplicated_low = []
        for event in low_risk_events:
            key_info = f"{event['event_id']}_{event['risk_desc']}_{event['timestamp'][:10]}"
            is_duplicate = False
            for saved_event in deduplicated_low:
                saved_key = f"{saved_event['event_id']}_{saved_event['risk_desc']}_{saved_event['timestamp'][:10]}"
                if self.similar(key_info, saved_key) > 0.9:  # 低风险使用90%阈值
                    is_duplicate = True
                    break
            if not is_duplicate:
                deduplicated_low.append(event)

        # 对中高风险事件，使用95%阈值去重
        for level in [2, 3]:  # 中高风险
            level_events = risk_groups[level]
            deduplicated_level = []
            for event in level_events:
                key_info = f"{event['event_id']}_{event['risk_desc']}_{event['timestamp'][:10]}"
                is_duplicate = False
                for saved_event in deduplicated_level:
                    saved_key = f"{saved_event['event_id']}_{saved_event['risk_desc']}_{saved_event['timestamp'][:10]}"
                    if self.similar(key_info, saved_key) > threshold:  # 中高风险使用95%阈值
                        is_duplicate = True
                        break
                if not is_duplicate:
                    deduplicated_level.append(event)
            filtered_results.extend(deduplicated_level)

        # 合并所有结果
        self.analysis_results = deduplicated_low + filtered_results

        print(f"中高风险去重后保留事件数量: {len(filtered_results)}")
        print(f"最终保留事件总数: {len(self.analysis_results)}")

    def count_risk_events(self):
        """统计各风险等级的事件数量"""
        risk_counts = {0: 0, 1: 0, 2: 0, 3: 0}

        for event in self.analysis_results:
            risk_level = event["risk_level"]
            risk_counts[risk_level] += 1

        # 输出统计结果
        print("\n风险事件统计:")
        print(f"无风险(0): {risk_counts[0]} 条")
        print(f"低风险(1): {risk_counts[1]} 条")
        print(f"中风险(2): {risk_counts[2]} 条")
        print(f"高风险(3): {risk_counts[3]} 条")

        return risk_counts

    def export_results(self, output_file=DEFAULT_RESULT_FILE):
        """导出分析结果到JSON文件"""
        try:
            # 对所有风险级别进行去重
            self.deduplicate_medium_high_risk()

            # 统计各风险类型的事件数量
            self.count_risk_events()

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.analysis_results, f, ensure_ascii=False, indent=2)
            print(f"分析结果已导出到 {output_file}")
            return True
        except Exception as e:
            print(f"导出结果时出错: {str(e)}")
            return False


def log_risk_judge(data):
    analyzer = LogAnalyzer(metadata=data)
    start_time = data.get('start_time')
    end_time = data.get('end_time')
    if not start_time or not end_time:
        print("错误: 传入的数据中缺少开始时间或结束时间。")
        return None
    logs_data = analyzer.log_detect(start_time, end_time)
    analyzer.export_to_json(logs_data)
    if analyzer.load_logs():
        analyzer.analyze_logs()
        if analyzer.export_results():
            with open(DEFAULT_RESULT_FILE, 'r', encoding='utf-8') as f:
                result = json.load(f)
            return result
    return None
