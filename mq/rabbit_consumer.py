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
        self.channel.basic_consume(
            queue=self.queue_name, on_message_callback=callback, auto_ack=True
        )
        print(
            f"[*] Waiting for messages in '{self.queue_name}' queue. To exit press CTRL+C"
        )
        self.channel.start_consuming()
