import pika
from config.rabbit_config import *


class RabbitProducer:

    def __init__(
        self,
        host=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD,
        virtual_host="",
    ):
        creds = pika.PlainCredentials(username, password)
        params = pika.ConnectionParameters(host=host, port=port, credentials=creds)
        self.connection = pika.BlockingConnection(params)
        self.channel = self.connection.channel()
        # self.channel.queue_declare(queue="hello", durable=True)

    def publish_message(self, exchange: str, routing_key: str, message: str):
        # 声明队列（如果不存在则创建）并设置持久化
        self.channel.queue_declare(queue=routing_key, durable=True)

        try:
            # 发送消息并设置持久化
            self.channel.basic_publish(
                exchange=exchange,
                routing_key=routing_key,
                body=message,
                properties=pika.BasicProperties(
                    delivery_mode=2,  # 使消息持久化
                ),
                mandatory=True,
            )
            # print(f"[*] 消息已成功发送到队列: {routing_key}")
        except Exception as e:
            print(f"[!] 发送消息时出错: {e}")
            raise e
