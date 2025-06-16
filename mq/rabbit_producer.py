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
        self.channel.queue_declare(queue=routing_key, durable=True)
        self.channel.basic_publish(
            exchange=exchange, routing_key=routing_key, body=message
        )
