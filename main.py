import logging

from mq.rabbit_producer import RabbitProducer
from mq.rabbit_consumer import RabbitConsumer
from password_detect.pwd_detect import password_detect
from system.pc_information import PcInfo
from utils.naming_convert import (
    underscore_to_camelcase,
    camelcase_to_underscore,
    rename_dict_key,
)
from detect.asset_detect import asset_detect

from vulnerability_scan.vulscan_main import vulnerability_scan
from config.rabbit_config import *
from detect.system_risk_detect import HostRiskDetector
from detect.hotfix_detect import hotfix_detect

import json
import time
import requests
import threading
import os


# HOST,  PORT, USERNAME, PASSWORD = ["192.168.152.128",  4568,  "admin",  "030924"]
def send_heart_beat(mac_address):
    while True:
        try:
            requests.post(
                "http://127.0.0.1:8080/heartbeat",
                json={"heartbeat": "1", "macAddress": mac_address},
            )
            time.sleep(1)
        except:
            print("Lost connection from server, agent will exit.")
            os._exit(0)


def create_asset_detect_message_callback(mac_address):
    def callback(ch, method, properties, body):
        print(f"[*] 从队列 agentQueue{mac_address} 收到消息")
        try:
            # 解码消息内容
            message_str = body.decode()
            print(f"[*] 收到消息: {message_str}")

            # 解析 JSON 数据（可能重复编码）
            try:
                data = json.loads(message_str)
                if isinstance(data, str):
                    data = json.loads(data)
            except json.JSONDecodeError as e:
                print(f"[!] JSON解析错误: {str(e)}")
                print(f"[!] 原始消息内容: {message_str}")
                raise e

            print(f"[*] 解析后的数据: {data}")

            # 确保 data 是字典
            if not isinstance(data, dict):
                print(f"[!] 数据格式错误，期望字典类型，实际是: {type(data)}")
                return

            # 验证 MAC 地址
            message_mac = data.get("info", {}).get("macAddress")
            if not message_mac:
                print(f"[!] 消息中未包含 MAC 地址")
                return

            if message_mac.upper() != mac_address.upper():
                print(f"[!] MAC 地址不匹配: 期望 {mac_address}, 实际 {message_mac}")
                return

            print("[*] MAC 地址验证通过")

            # 命名风格转换
            data = rename_dict_key(data, camelcase_to_underscore)

            detect_type = data.get("info", {}).get("type")
            detect_result = None
            queue_name = None

            if detect_type == "assets":
                detect_result = asset_detect(data)
                queue_name = "detect_result"
            elif detect_type == "vulnerability":
                detect_result = vulnerability_scan(data)
                queue_name = "vul_scan_result"
            elif detect_type == "system":
                detector = HostRiskDetector()
                detector.detect_all_risks()
                detect_result = detector.generate_report()
                queue_name = "system_detect_queue"
            elif detect_type == "hotfix":
                detect_result = hotfix_detect(data)
                queue_name = "hotfix_detect_result"
            elif detect_type == "password":
                detect_result = password_detect(data)
                queue_name = "pwd_detect_result"
            else:
                print(f"[!] 未知检测类型: {detect_type}")
                return

            if detect_result and queue_name:
                print(f"[*] 发送检测结果到 {queue_name} 队列")
                print(f"[*] 发送的 JSON 数据: {detect_result}")
                producer = RabbitProducer(
                    host=HOST, port=PORT, username=USERNAME, password=PASSWORD
                )
                producer.publish_message(
                    "", queue_name, json.dumps(detect_result, ensure_ascii=False)
                )

        except Exception as e:
            print(f"[!] 处理消息时出错: {str(e)}")
            import traceback

            traceback.print_exc()
            raise e

    return callback


if __name__ == "__main__":
    info = PcInfo()
    producer = RabbitProducer(
        host=HOST, port=PORT, username=USERNAME, password=PASSWORD
    )
    info_data = {underscore_to_camelcase(k): v for k, v in info.get_info_dict().items()}

    # 发送一次消息
    producer.publish_message("", routing_key="hello", message=json.dumps(info_data))

    # 启动心跳线程
    heartbeat_thread = threading.Thread(
        target=send_heart_beat, args=(info_data["macAddress"],), daemon=True
    )
    heartbeat_thread.start()

    # 创建消费者实例
    consumer = RabbitConsumer(
        host=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD,
        queue_name=f"agentQueue" + info_data["macAddress"].replace(":", ""),
    )

    # 创建消息回调函数
    message_callback = create_asset_detect_message_callback(info_data["macAddress"])

    # 启动消费者线程
    consumer_thread = threading.Thread(
        target=consumer.start_consuming,
        args=(message_callback,),
        daemon=True,
    )
    consumer_thread.start()

    input()
