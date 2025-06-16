package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.VulScanService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.lang.annotation.Retention;
import java.util.HashMap;

@RestController
public class VulScanController {

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
}
