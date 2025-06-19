package com.tpp.threat_perception_platform.service.impl;

import com.alibaba.fastjson.JSON;
import com.tpp.threat_perception_platform.dao.AccountMapper;
import com.tpp.threat_perception_platform.service.PwdService;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import com.tpp.threat_perception_platform.utils.RedisCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
public class PwdServiceImpl implements PwdService {

    private static final Logger logger = LoggerFactory.getLogger(PwdServiceImpl.class);

    @Autowired
    private RabbitMQService rabbitMQService;
    @Autowired
    private RedisCache redisCache;
    @Autowired
    private AccountMapper accountMapper;

    @Override
    public HashMap<String, Object> pwdDetect(HashMap<String, Object> data) {
        HashMap<String, Object> result = new HashMap<>();

        try {
            // 字段提取与校验
            if (!data.containsKey("id") || !data.containsKey("hostName") || !data.containsKey("macAddress") || !data.containsKey("type")) {
                throw new IllegalArgumentException("字段缺失");
            }


            Integer id = Integer.parseInt(data.get("id").toString());
            String hostName = data.get("hostName").toString();
            String originMacAddress = data.get("macAddress").toString();
            String macAddress = data.get("macAddress").toString().replace(":", "");
            String type = data.get("type").toString();

            // 构建消息体
            HashMap<String, Object> messageMap = new HashMap<>();
            messageMap.put("hostName", hostName);
            messageMap.put("macAddress", originMacAddress);
            messageMap.put("type", "password");
            messageMap.put("id", id);
            messageMap.put("detectPwd", "on".equals(data.get("detect-pwd")));
            System.out.println(messageMap);
            if (redisCache.getCacheObject("Heartbeat from " + originMacAddress) == null) {
                throw new IllegalAccessException("主机不在线！无法进行弱密码检测");
            }

            // 发送消息（默认 exchange，队列名以 MAC 地址标识）
            rabbitMQService.sendMessage("", "agentQueue" + macAddress, JSON.toJSONString(messageMap));

            // 成功响应
            result.put("code", 0);
            result.put("msg", "接收成功");
        } catch (IllegalArgumentException e) {
            // 错误响应
            result.put("code", 1001);
            result.put("msg", "字段格式有误");
        } catch (IllegalAccessException e) {
            result.put("code", 1002);
            result.put("msg", e.getMessage());
            return result;
        }

        return result;
    }

    @Override
    public int getWeakPasswordCount() {
        int count = accountMapper.countWeakPasswords();
        logger.info("当前账户总数: {}", count);
        return count;
    }
}
