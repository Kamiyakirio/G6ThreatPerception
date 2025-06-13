import pika


class RabbitProducer:

    def __init__(
        self,
        host="192.168.147.143",
        port=4568,
        username="admin",
        password="20250606",
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
