package com.tpp.threat_perception_platform.service;

public interface RabbitMQService {
    void createQueue(String queueName);

    boolean queueExists(String queueName);

    boolean deleteQueue(String queueName);

    void sendMessage(String exchangeName, String queueName, String routingKey, String message);

    void sendMessage(String exchangeName, String routingKey, String message);
    
    /**
     * 处理补丁检测结果
     * @param message 消息内容
     */
    void handleHotfixDetectResult(String message);
}
