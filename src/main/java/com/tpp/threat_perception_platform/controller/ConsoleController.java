package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.UserService;
import com.tpp.threat_perception_platform.service.HostService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/console")
public class ConsoleController {

    @Autowired
    private UserService userService;

    @Autowired
    private HostService hostService;

    /**
     * 获取控制台基础数据
     * @return 基础数据，包括用户数量等
     */
    @GetMapping("/basic-data")
    public ResponseResult<Map<String, Object>> getBasicData() {
        Map<String, Object> data = new HashMap<>();
        // 获取用户数量
        data.put("userCount", userService.getTotalUserCount());
        
        // 获取主机统计数据
        HashMap<String, Integer> hostStats = hostService.getHostStatistics();
        data.put("onlineHostCount", hostStats.get("onlineCount")); // 在线主机数
        data.put("detectedHostCount", hostStats.get("detectedCount")); // 已探测主机数
        
        return new ResponseResult<>(200, "获取成功", data);
    }
} 