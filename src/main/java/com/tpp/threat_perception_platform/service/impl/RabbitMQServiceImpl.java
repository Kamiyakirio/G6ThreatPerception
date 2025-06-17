package com.tpp.threat_perception_platform.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tpp.threat_perception_platform.service.HotfixResultService;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.EnableRabbit;
import com.rabbitmq.client.Channel;
import org.springframework.amqp.support.AmqpHeaders;
import org.springframework.messaging.handler.annotation.Header;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.util.List;
import java.util.Map;

@Service
@EnableRabbit
public class RabbitMQServiceImpl implements RabbitMQService {
    
    private static final Logger logger = LoggerFactory.getLogger(RabbitMQServiceImpl.class);

    @Autowired
    private RabbitAdmin rabbitAdmin;

    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Autowired
    private HotfixResultService hotfixResultService;

    @PostConstruct
    public void init() {
        // 确保队列存在
        Queue queue = new Queue("hotfix_detect_result", true);
        rabbitAdmin.declareQueue(queue);
        logger.info("已创建hotfix_detect_result队列");
    }

    @Override
    public void createQueue(String queueName) {
        Queue queue = new Queue(queueName, true);
        rabbitAdmin.declareQueue(queue);
        logger.info("创建队列: {}", queueName);
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
        logger.info("已发送消息到 [{}]：{}", queueName, message);
    }

@Override
public void sendMessage(String exchangeName, String routingKey, String message) {
    String queueName = routingKey;

    DirectExchange exchange = new DirectExchange(exchangeName, true, false);
    rabbitAdmin.declareExchange(exchange);

    Queue queue = new Queue(queueName, true);
    rabbitAdmin.declareQueue(queue);

    Binding binding = BindingBuilder.bind(queue).to(exchange).with(routingKey);
    rabbitAdmin.declareBinding(binding);

    rabbitTemplate.convertAndSend(exchangeName, routingKey, message);

    System.out.println("【使用 routingKey=" + routingKey + " 作为队列】消息发送成功: " + message);
}

@Override
public void handleHotfixDetectResult(String message) {
    try {
        System.out.println("开始处理补丁检测结果消息");
        System.out.println("收到补丁检测结果消息: " + message);

//        String innerJson = objectMapper.readValue(message, String.class);
        List<Map<String, String>> result = objectMapper.readValue(message, new TypeReference<List<Map<String, String>>>() {});
        
        System.out.println("消息解析成功，包含 " + result.size() + " 条记录");

        int count = hotfixResultService.processHotfixResults(result);
        System.out.println("成功处理 " + count + " 条补丁检测结果");
    } catch (Exception e) {
        System.out.println("处理补丁检测结果失败: " + e.getMessage());
        e.printStackTrace();
        throw new RuntimeException("处理补丁检测结果失败", e);
    }
}

@RabbitListener(queues = "hotfix_detect_result")
public void handleHotfixDetectResultMessage(Message message, Channel channel) throws IOException {
    long tag = message.getMessageProperties().getDeliveryTag();
    try {
        String messageBody = new String(message.getBody());
        handleHotfixDetectResult(messageBody);

        channel.basicAck(tag, false);
        System.out.println("消息已确认，deliveryTag: " + tag);
    } catch (Exception e) {
        System.out.println("处理补丁检测结果失败: " + e.getMessage());
        e.printStackTrace();
        channel.basicNack(tag, false, false);
        System.out.println("消息处理失败，已重新入队，deliveryTag: " + tag);
    }
}
}
