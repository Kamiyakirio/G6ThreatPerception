package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.LogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class LogDetectController {

    @Autowired
    private LogService logService;

    @PostMapping("/log/log_detect")
    public ResponseResult logDetect(@RequestBody Map<String, Object> data) {
        return logService.logDetect(data);
    }
    
    @PostMapping("/log/check_logs")
    public ResponseResult checkLogs(@RequestBody Map<String, Object> data) {
        return logService.checkLogs(data);
    }
    
    @PostMapping("/log/get_latest_log_time")
    public ResponseResult getLatestLogTime(@RequestBody Map<String, Object> data) {
        return logService.getLatestLogTime(data);
    }
    
    @PostMapping("/log/set_sync_interval")
    public ResponseResult setSyncInterval(@RequestBody Map<String, Object> data) {
        return logService.setSyncInterval(data);
    }
} 