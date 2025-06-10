package com.tpp.threat_perception_platform.service.impl;

import com.tpp.threat_perception_platform.service.RabbitMQService;
import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RabbitMQServiceImpl implements RabbitMQService {

    @Autowired
    private RabbitAdmin rabbitAdmin;

    @Autowired
    private RabbitTemplate rabbitTemplate;


    @Override
    public void createQueue(String queueName) {
        Queue queue = new Queue(queueName, true);
        rabbitAdmin.declareQueue(queue);
    }

    @Override
    public boolean queueExists(String queueName) {
        return rabbitAdmin.getQueueProperties(queueName) != null;
    }

    @Override
    public boolean deleteQueue(String queueName) {
        return rabbitAdmin.deleteQueue(queueName);
    }

    @Override
    public void sendMessage(String exchangeName, String queueName, String routingKey, String message) {
        // 声明 exchange
        DirectExchange exchange = new DirectExchange(exchangeName, true, false);
        rabbitAdmin.declareExchange(exchange);

        // 声明 queue
        Queue queue = new Queue(queueName, true);
        rabbitAdmin.declareQueue(queue);

        // 绑定 queue 到 exchange
        Binding binding = BindingBuilder.bind(queue).to(exchange).with(routingKey);
        rabbitAdmin.declareBinding(binding);

        // 发送消息
        rabbitTemplate.convertAndSend(exchangeName, routingKey, message);
        System.out.printf("已发送消息到 [%s]：%s\n", queueName, message);
    }

    @Override
    public void sendMessage(String exchangeName, String routingKey, String message) {
        // 使用 routingKey 作为队列名
        String queueName = routingKey;

        // 声明 exchange（direct 类型）
        DirectExchange exchange = new DirectExchange(exchangeName, true, false);
        rabbitAdmin.declareExchange(exchange);

        // 声明 queue
        Queue queue = new Queue(queueName, true);
        rabbitAdmin.declareQueue(queue);

        // 绑定 queue 到 exchange
        Binding binding = BindingBuilder.bind(queue).to(exchange).with(routingKey);
        rabbitAdmin.declareBinding(binding);

        // 发送消息
        rabbitTemplate.convertAndSend(exchangeName, routingKey, message);
        System.out.printf("【使用 routingKey=%s 作为队列】消息发送成功: %s\n", routingKey, message);
    }
}
