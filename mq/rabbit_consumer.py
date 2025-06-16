# rabbit_consumer.py

import pika
from config.rabbit_config import *


class RabbitConsumer:

    def __init__(
        self,
        host=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD,
        virtual_host="",
        queue_name="hello",
    ):
        self.queue_name = queue_name
        creds = pika.PlainCredentials(username, password)
        params = pika.ConnectionParameters(host=host, port=port, credentials=creds)
        self.connection = pika.BlockingConnection(params)
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=queue_name, durable=True)

    def start_consuming(self, callback):
        def wrapped_callback(ch, method, properties, body):
            try:
                # print(f"[*] 收到消息: {body.decode()}")
                callback(ch, method, properties, body)
                # print("[*] 消息处理完成")
                ch.basic_ack(delivery_tag=method.delivery_tag)
            except Exception as e:
                # print(f"[!] 处理消息时出错: {e}")
                ch.basic_ack(delivery_tag=method.delivery_tag)

        self.channel.basic_qos(prefetch_count=1)  # 每次只处理一条消息
        self.channel.basic_consume(
            queue=self.queue_name,
            on_message_callback=wrapped_callback,
            auto_ack=False,  # 关闭自动确认
        )
        print(
            f"[*] Waiting for messages in '{self.queue_name}' queue. To exit press CTRL+C"
        )
        self.channel.start_consuming()
