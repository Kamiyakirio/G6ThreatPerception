package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.pojo.Role;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.HostService;
import com.tpp.threat_perception_platform.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
public class HostController {

    @Autowired
    private HostService hostService;

    @PostMapping("/host/list")
    public ResponseResult hostList(MyParam param){
        return hostService.findAll(param);
    }

    @PostMapping("/host/delete")
    public ResponseResult hostDelete(@RequestParam("ids[]") Integer[] ids){
        return hostService.delete(ids);
    }

    @PostMapping("/host/detect")
    public HashMap<String,Object> hostDetect(@RequestBody HashMap<String,Object> data){
        return hostService.hostDetect(data);
    }
}
