package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.service.PwdService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class PwdDetectController {
    
    private static final Logger logger = LoggerFactory.getLogger(PwdDetectController.class);

    @Autowired
    private PwdService pwdService;

    @PostMapping("/risk/pwd_detect")
    public HashMap<String,Object> pwdDetect(@RequestBody HashMap<String,Object> data){
        return pwdService.pwdDetect(data);
    }

    /**
     * 获取弱密码统计数据
     */
    @GetMapping("/pwd/statistics")
    public Map<String, Object> getStatistics() {
        int count = pwdService.getWeakPasswordCount();
        logger.info("返回账户统计数据: {}", count);
        
        Map<String, Object> result = new HashMap<>();
        result.put("code", 0);
        result.put("data", count);
        return result;
    }
}
