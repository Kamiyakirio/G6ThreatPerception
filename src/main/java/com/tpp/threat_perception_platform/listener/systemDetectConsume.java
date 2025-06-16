package com.tpp.threat_perception_platform.listener;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.tpp.threat_perception_platform.dao.SystemDetectMapper;
import com.tpp.threat_perception_platform.pojo.SystemDetect;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class systemDetectConsume {

    @Autowired
    private SystemDetectMapper systemDetectMapper;

    @RabbitListener(queues = "system_detect_queue")
    public void processMessage(Message message) {
//        System.out.println("【收到消息】" + message);
            try {
                String messageBody = new String(message.getBody(), StandardCharsets.UTF_8);
                JSONObject json = JSON.parseObject(messageBody);
                JSONObject hostInfo = json.getJSONObject("host_info");
                JSONArray detectionResults = json.getJSONArray("detection_results");

                String macAddress = hostInfo.getString("mac_address");
                // 假设 mac_address 替换为 ip_address

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

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
}


