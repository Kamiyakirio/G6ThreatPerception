# main.py（扩展）

from mq.rabbit_producer import RabbitProducer
from mq.rabbit_consumer import RabbitConsumer  # ← 新导入
from system.pc_information import PcInfo
from utils.naming_convert import underscore_to_camelcase

import json
import time
import requests
import threading
import sys


def send_heart_beat(mac_address):
    while True:
        requests.post(
            "http://127.0.0.1:8080/heartbeat",
            json={"heartbeat": "1", "macAddress": mac_address},
        )
        time.sleep(1)


def on_message_callback(ch, method, properties, body):
    data = body.decode()
    data_dict = json.loads(data)
    print(f"[✔] Received message: {body.decode()}")


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

    # 启动消费者线程
    consumer = RabbitConsumer(
        queue_name=f"agentQueue" + info_data["macAddress"].replace(":", "")
    )
    consumer_thread = threading.Thread(
        target=consumer.start_consuming, args=(on_message_callback,), daemon=True
    )
    consumer_thread.start()

    input()
