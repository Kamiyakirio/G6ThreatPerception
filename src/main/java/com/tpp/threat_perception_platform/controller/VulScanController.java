package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.VulScanService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.lang.annotation.Retention;
import java.util.HashMap;
import java.util.Map;

@RestController
public class VulScanController {

    private static final Logger logger = LoggerFactory.getLogger(VulScanController.class);

    @Autowired
    private VulScanService vulScanService;

    @PostMapping("/detect/vul_scan")
    public ResponseResult detectVulScan(@RequestBody HashMap<String,Object> data) {
        return vulScanService.createVulScanTask(data);
    }

    @PostMapping("/detect/scan_result")
    public ResponseResult getScanResult(@RequestBody HashMap<String,Object> data) {
        return vulScanService.getScanResult(data);
    }

    /**
     * 获取漏洞检测统计数据
     */
    @GetMapping("/vul/statistics")
    public Map<String, Object> getStatistics() {
        int count = vulScanService.getVulCount();
//        logger.info("当前漏洞检测总数: {}", count);
        
        Map<String, Object> result = new HashMap<>();
        result.put("code", 0);
        result.put("data", count);
        return result;
    }
}
