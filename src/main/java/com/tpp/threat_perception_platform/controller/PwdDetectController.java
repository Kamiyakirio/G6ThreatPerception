package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.service.PwdService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
public class PwdDetectController {

    @Autowired
    private PwdService pwdService;
    @PostMapping("/risk/pwd_detect")
    public HashMap<String,Object> pwdDetect(@RequestBody HashMap<String,Object> data){
        return pwdService.pwdDetect(data);
    }
}
