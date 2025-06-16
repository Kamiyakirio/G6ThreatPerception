package com.tpp.threat_perception_platform.controller; // 添加此行

import com.tpp.threat_perception_platform.param.SystemDetectParam;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.HostService;
import com.tpp.threat_perception_platform.service.SystemDetectService;
import com.tpp.threat_perception_platform.utils.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
@RestController
@RequestMapping("/host")
public class SystemDetectController {

    @Autowired
    private SystemDetectService systemDetectService;

    @Autowired
    private HostService hostService;

    @PostMapping("/detectedList")
    public Result detectedList() {
        List<Map<String, Object>> list = systemDetectService.getDetectedHosts();
        return Result.success(list);
    }

    @GetMapping("/riskDetails/{macAddress}")
    public Result getRiskDetails(@PathVariable String macAddress) {
        List<Map<String, Object>> riskDetails = systemDetectService.getSystemDetectByMac(macAddress);
        return Result.success(riskDetails);
    }

    @PostMapping("/systemDetect")
    public ResponseResult systemDetect(@RequestBody SystemDetectParam param) {
        return systemDetectService.systemDetect(param);
    }





}
