import pika


class RabbitProducer:

    def __init__(self):
        creds = pika.PlainCredentials("admin", "admin")
        params = pika.ConnectionParameters(
            host="192.168.253.133", port=5672, credentials=creds
        )
        self.connection = pika.BlockingConnection(params)
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue="hello", durable=True)

    def publish_message(self, routing_key: str, message: str):
        self.channel.basic_publish(exchange="", routing_key=routing_key, body=message)


# 创建队列（持久化）
channel.queue_declare(queue="hello", durable=True)

# 发送消息
channel.basic_publish(
    exchange="",
    routing_key="hello",
    body="Hello RabbitMQ!",
    properties=pika.BasicProperties(delivery_mode=2),  # 消息持久化
)
print(" [x] Sent 'Hello RabbitMQ!'")
connection.close()
