from mq.rabbit_producer import RabbitProducer
from mq.rabbit_consumer import RabbitConsumer
from password_detect.pwd_detect import password_detect
from system.pc_information import PcInfo
from utils.naming_convert import underscore_to_camelcase, camelcase_to_underscore
from detect.asset_detect import asset_detect

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
            os._exit(0)


def create_asset_detect_message_callback(mac_address):
    def callback(ch, method, properties, body):
        data = json.loads(body.decode())
        data = {camelcase_to_underscore(k): v for k, v in data.items()}
        detect_result = asset_detect(data)
        producer = RabbitProducer()
        producer.publish_message("", "detect_result", detect_result)

    return callback


def create_pwd_detect_message_callback(mac_address):
    def callback(ch, method, properties, body):
        data = json.loads(body.decode())
        data = {camelcase_to_underscore(k): v for k, v in data.items()}
        pwd_detect_result = password_detect(data)
        producer.publish_message(
            "",
            "pwd_detect_result",
    pwd_detect_result
        )

    return callback


if __name__ == "__main__":
    info = PcInfo()
    producer = RabbitProducer()
    info_data = {underscore_to_camelcase(k): v for k, v in info.get_info_dict().items()}

    # 发送一次消息
    producer.publish_message("", routing_key="hello", message=json.dumps(info_data))

    # 启动心跳线程
    heartbeat_thread = threading.Thread(
        target=send_heart_beat, args=(info_data["macAddress"],), daemon=True
    )
    heartbeat_thread.start()

    # 资产探测监听队列：agentQueue + mac地址（无冒号）
    asset_queue_name = f"agentQueue{info_data['macAddress'].replace(':', '')}"
    asset_detect_message_consumer = RabbitConsumer(queue_name=asset_queue_name)
    asset_detect_message_callback = create_asset_detect_message_callback(info_data["macAddress"])
    asset_detect_consumer_thread = threading.Thread(
        target=asset_detect_message_consumer.start_consuming,
        args=(asset_detect_message_callback,),
        daemon=True,
    )
    asset_detect_consumer_thread.start()

    # 弱口令检测监听队列：agentPwdQueue + mac地址（无冒号）
    pwd_queue_name = f"agentPwdQueue{info_data['macAddress'].replace(':', '')}"
    pwd_detect_message_consumer = RabbitConsumer(queue_name=pwd_queue_name)
    pwd_detect_message_callback = create_pwd_detect_message_callback(info_data["macAddress"])
    pwd_detect_consumer_thread = threading.Thread(
        target=pwd_detect_message_consumer.start_consuming,
        args=(pwd_detect_message_callback,),
        daemon=True,
    )
    pwd_detect_consumer_thread.start()

    input()

