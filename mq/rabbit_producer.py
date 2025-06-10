import pika


class RabbitProducer:

    def __init__(
        self,
        host="192.168.253.134",
        port=5672,
        username="admin",
        password="admin",
        virtual_host="",
    ):
        creds = pika.PlainCredentials(username, password)
        params = pika.ConnectionParameters(host=host, port=port, credentials=creds)
        self.connection = pika.BlockingConnection(params)
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue="hello", durable=True)

    def publish_message(self, exchange: str, routing_key: str, message: str):
        self.channel.basic_publish(
            exchange=exchange, routing_key=routing_key, body=message
        )
