import logging

from mq.rabbit_producer import RabbitProducer
from mq.rabbit_consumer import RabbitConsumer
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

import json
import time
import requests
import threading
import os


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
        print("Received message:", body)
        data = json.loads(body.decode())

        # 使用统一的 key 转换方式
        data = rename_dict_key(data, camelcase_to_underscore)

        detect_result = None

        if data["info"]["type"] == "assets":
            detect_result = asset_detect(data)
        elif data["info"]["type"] == "vulnerability":
            detect_result = vulnerability_scan(data)
        elif data["info"]["type"] == "system":
            detector = HostRiskDetector()
            detector.detect_all_risks()
            detect_result = detector.generate_report()

        # 初始化 RabbitMQ 生产者
        producer = RabbitProducer(
            host=HOST, port=PORT, username=USERNAME, password=PASSWORD
        )

        # 队列根据类型动态选择
        if data["info"]["type"] == "system":
            queue_name = "system_detect_queue"
        elif data["info"]["type"] == "vulnerability":
            queue_name = "vul_scan_result"
        else:
            queue_name = "detect_result"

        producer.publish_message(
            "", queue_name, json.dumps(detect_result, ensure_ascii=False)
        )

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

    asset_detect_message_consumer = RabbitConsumer(
        host=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD,
        queue_name=f"agentQueue" + info_data["macAddress"].replace(":", ""),
    )
    asset_detect_message_callback = create_asset_detect_message_callback(
        info_data["macAddress"]
    )
    asset_detect_consumer_thread = threading.Thread(
        target=asset_detect_message_consumer.start_consuming,
        args=(asset_detect_message_callback,),
        daemon=True,
    )
    asset_detect_consumer_thread.start()

    input()
