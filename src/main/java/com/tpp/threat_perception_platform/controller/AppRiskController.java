package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.AppRiskService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

@RestController
public class AppRiskController {

    @Autowired
    private AppRiskService appRiskService;

    @PostMapping("/apprisk/trigger")
    public ResponseResult triggerAppRiskDetect(@RequestBody HashMap<String, String> data) {
        System.out.println("收到/apprisk/trigger请求，数据: " + data);
        String macAddress = data.get("macAddress");
        if (macAddress == null || macAddress.isEmpty()) {
            System.out.println("MAC地址为空！");
            return new ResponseResult(1001, "MAC地址不能为空！");
        }
        System.out.println("MAC地址: " + macAddress);
        return appRiskService.triggerAppRiskDetect(macAddress);
    }

    @GetMapping("/apprisk/checkStatus")
    public ResponseResult checkDetectionStatus(@RequestParam("macAddress") String macAddress) {
        return appRiskService.checkDetectionStatus(macAddress);
    }

    @PostMapping("/apprisk/list")
    public ResponseResult getAppRiskResults(
            @RequestParam("macAddress") String macAddress,
            @RequestParam("page") Integer page,
            @RequestParam("limit") Integer limit) {
//        System.out.println("收到/apprisk/list请求，macAddress: " + macAddress + ", page: " + page + ", limit: " + limit);
        return appRiskService.getAppRiskResults(macAddress, page, limit);
    }

    @GetMapping("/apprisk/total")
    public ResponseResult getAppRiskTotal() {
        return appRiskService.getAppRiskTotal();
    }
} 