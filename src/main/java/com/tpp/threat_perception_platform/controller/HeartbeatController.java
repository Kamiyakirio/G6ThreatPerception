package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.dao.HostMapper;
import com.tpp.threat_perception_platform.pojo.Host;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.utils.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.concurrent.TimeUnit;

@RestController
public class HeartbeatController {

    @Autowired
    private RedisCache redisCache;

    @Autowired
    private HostMapper hostMapper;

    @PostMapping("/heartbeat")
    public HashMap<String, Object> heartbeat(@RequestBody HashMap<String, Object> map) {
        if (map.get("heartbeat") == null || !map.get("heartbeat").equals("1")) {
            return null;
        }
        if (map.get("macAddress") == null) {
            return null;
        }
        String macAddress = map.get("macAddress").toString();
        String cacheString = "Heartbeat from " + macAddress;

        if (redisCache.getCacheObject(cacheString) == null) {
            Host result = hostMapper.selectByMacAddress(macAddress);
            if (result == null) {
                return null;
            }
            result.setIsAlive(1);
            hostMapper.updateByPrimaryKey(result);
        }

        redisCache.setCacheObject(cacheString, "", 5, TimeUnit.SECONDS);
        HashMap<String, Object> response = new HashMap<>();
        response.put("ok", 1);
        return response;
    }
}
