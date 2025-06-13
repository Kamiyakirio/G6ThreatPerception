from mq.rabbit_producer import RabbitProducer
from mq.rabbit_consumer import RabbitConsumer
from system.pc_information import PcInfo
from utils.naming_convert import underscore_to_camelcase, camelcase_to_underscore
from detect.asset_detect import asset_detect
from config.rabbit_config import *
from detect.hotfix_detect import hotfix_detect

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
        print(f"[*] 从队列 agentQueue{mac_address} 收到消息")
        try:
            # 解码消息内容
            message_str = body.decode()
            print(f"[*] 收到消息: {message_str}")
            
            # 解析JSON数据（可能需要解析两次，因为消息可能被重复编码）
            try:
                data = json.loads(message_str)
                # 如果data是字符串，说明可能是重复编码的JSON
                if isinstance(data, str):
                    data = json.loads(data)
            except json.JSONDecodeError as e:
                print(f"[!] JSON解析错误: {str(e)}")
                print(f"[!] 原始消息内容: {message_str}")
                raise e
                
            print(f"[*] 解析后的数据: {data}")
            
            # 确保data是字典类型
            if not isinstance(data, dict):
                print(f"[!] 数据格式错误，期望字典类型，实际是: {type(data)}")
                return
                
            detect_result = None
            queue_name = None

            if data.get('info', {}).get('type') == 'assets':
                # 对于资产检测，需要转换命名风格
                converted_data = {camelcase_to_underscore(k): v for k, v in data.items()}
                detect_result = asset_detect(converted_data)
                queue_name = "detect_result"
            elif data.get('info', {}).get('type') == 'hotfix':
                # 对于补丁检测，直接传递数据
                detect_result = hotfix_detect(data)
                queue_name = "hotfix_detect_result"
            else:
                print(f"未知检测类型: {data.get('info', {}).get('type')}")
                return
                
            if detect_result and queue_name:
                print(f"[*] 发送检测结果到{queue_name}队列")
                print(f"[*] 发送的JSON数据: {detect_result}")
                producer = RabbitProducer(
                    host=HOST, port=PORT, username=USERNAME, password=PASSWORD
                )
                producer.publish_message("", queue_name, detect_result)
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
    message_callback = create_asset_detect_message_callback(
        info_data["macAddress"]
    )
    
    # 启动消费者线程
    consumer_thread = threading.Thread(
        target=consumer.start_consuming,
        args=(message_callback,),
        daemon=True,
    )
    consumer_thread.start()

    input()
