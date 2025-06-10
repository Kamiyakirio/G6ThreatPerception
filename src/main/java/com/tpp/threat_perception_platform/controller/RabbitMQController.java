package com.tpp.threat_perception_platform.controller;

import com.alibaba.fastjson.JSON;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.tpp.threat_perception_platform.dao.HostMapper;
import com.tpp.threat_perception_platform.pojo.Host;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.amqp.RabbitProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;

@Component
public class RabbitMQController {

    @Autowired
    private HostMapper hostMapper;

    @RabbitListener(queues = "hello")
    public void receiveHostInfo(String messageBody, Message message, Channel channel) throws IOException {
        long tag = message.getMessageProperties().getDeliveryTag();
//        System.out.println(messageBody);

        Host host = new Host();
        HashMap<String, Object> dataDict = JSON.parseObject(messageBody, HashMap.class);

        host.setMacAddress(dataDict.get("macAddress").toString());
        host.setHostName(dataDict.get("pcName").toString());
        host.setIpAddress(dataDict.get("ipAddress").toString());
        host.setOsType(dataDict.get("osName").toString());
        host.setOsName(dataDict.get("osName").toString() + " "+dataDict.get("osNameDetailed").toString());
        host.setCpuName(dataDict.get("cpuInfo").toString());
        host.setOsBit(dataDict.get("osBit").toString());
        host.setRam(dataDict.get("memorySize").toString());

        Host savedResult = hostMapper.selectByMacAddress(host.getMacAddress());
        if (savedResult != null) {
            host.setUpdateTime(new Date(System.currentTimeMillis()));
            host.setId(savedResult.getId());
            hostMapper.updateByPrimaryKeySelective(host);
        } else {
            host.setCreateTime(new Date(System.currentTimeMillis()));
            hostMapper.insert(host);
        }

        channel.basicAck(tag, false);
    }
}
