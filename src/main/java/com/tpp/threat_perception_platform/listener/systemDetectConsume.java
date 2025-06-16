package com.tpp.threat_perception_platform.listener;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.tpp.threat_perception_platform.dao.SystemDetectMapper;
import com.tpp.threat_perception_platform.pojo.SystemDetect;
import org.springframework.amqp.core.Message;
import org.slf4j.Logger;
import com.rabbitmq.client.Channel;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.util.Date;

@Component
public class systemDetectConsume {

    private static final Logger logger = LoggerFactory.getLogger(systemDetectConsume.class);

    @Autowired
    private SystemDetectMapper systemDetectMapper;

    @RabbitListener(queues = "system_detect_queue")
    public void processMessage(String messageBody, Message message, Channel channel)  throws IOException {
        long tag=message.getMessageProperties().getDeliveryTag();
//        System.out.println("【收到消息】" + message);
            try {
                JSONObject json = JSON.parseObject(messageBody);
                JSONObject hostInfo = json.getJSONObject("host_info");
                JSONArray detectionResults = json.getJSONArray("detection_results");


            String macAddress = hostInfo.getString("mac_address");

            // 查询当前 macAddress 已有多少条记录
            Integer count = systemDetectMapper.countByMacAddress(macAddress);
            Integer sDetectId = count == null ? 1 : count + 1;

            for (int i = 0; i < detectionResults.size(); i++) {
                JSONObject result = detectionResults.getJSONObject(i);

                String detectProgram = result.getString("探测项目");
                String riskLevel = result.getString("风险等级");
                String details = result.getString("详情");
                String suggest = result.getString("建议");

                SystemDetect systemDetect = new SystemDetect();
                systemDetect.setMacAddress(macAddress);
                systemDetect.setDetectProgram(detectProgram);
                systemDetect.setRiskLevel(riskLevel);
                systemDetect.setDetails(details);
                systemDetect.setSuggest(suggest);
                systemDetect.setsDetectId(sDetectId); // 第几次入库
                systemDetect.setDetectTime(new Date());

                systemDetectMapper.insert(systemDetect);
            }

            logger.info("【消息处理完成】");

            // 成功处理后手动确认
            if (channel.isOpen()) {
                channel.basicAck(tag, false);
            } else {
                logger.warn("Channel is not open, cannot acknowledge message.");
            }

        } catch (Exception e) {
            logger.error("【消息处理异常】", e);

            // 异常时拒绝消息并重新入队
            if (channel.isOpen()) {
                channel.basicAck(tag, false);
            } else {
                logger.warn("Channel is not open, cannot reject message.");
            }
        }
    }
}