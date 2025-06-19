package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.AssetsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class AssetsController {

    @Autowired
    private AssetsService assetsService;

    @PostMapping("/host/detect_result/account")
    public ResponseResult accountList(@RequestParam Integer page, @RequestParam Integer limit, @RequestParam String macAddress){

        MyParam myParam = new MyParam();
        myParam.setPage(page);
        myParam.setLimit(limit);

        return assetsService.accountList(myParam, macAddress);

    }

    @PostMapping("/host/detect_result/service")
    public ResponseResult serviceList(@RequestParam Integer page, @RequestParam Integer limit, @RequestParam String macAddress){

        MyParam myParam = new MyParam();
        myParam.setPage(page);
        myParam.setLimit(limit);

        return assetsService.serviceList(myParam, macAddress);

    }

    @PostMapping("/host/detect_result/app")
    public ResponseResult appList(@RequestParam Integer page, @RequestParam Integer limit, @RequestParam String macAddress){

        MyParam myParam = new MyParam();
        myParam.setPage(page);
        myParam.setLimit(limit);

        return assetsService.appList(myParam, macAddress);

    }

    @PostMapping("/host/detect_result/process")
    public ResponseResult processList(@RequestParam Integer page, @RequestParam Integer limit, @RequestParam String macAddress){

        MyParam myParam = new MyParam();
        myParam.setPage(page);
        myParam.setLimit(limit);

        return assetsService.processList(myParam, macAddress);

    }

    @GetMapping("/assets/statistics")
    public ResponseResult getAssetsStatistics() {
        Map<String, Integer> statistics = assetsService.getAssetsStatistics();
        return new ResponseResult(0, "获取资产统计成功", statistics);
    }
}