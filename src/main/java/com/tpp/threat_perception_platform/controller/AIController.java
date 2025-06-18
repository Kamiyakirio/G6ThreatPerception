package com.tpp.threat_perception_platform.controller;

import com.alibaba.fastjson.JSON;
import com.tpp.threat_perception_platform.asset.Account;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.AIService;
import com.tpp.threat_perception_platform.utils.TextFileLoader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class AIController {

    @Autowired
    private AIService aiService;

    @PostMapping("/ai/account_analysis")
    public ResponseResult AIAccountAnalysis(@RequestBody List<Account> accounts)
    {
        String prompt= TextFileLoader.loadTextFile("texts/prompts/account_analysis_prompt.txt");
        String result = aiService.aiAssistWithPrompt(prompt, JSON.toJSONString(accounts));
        return new ResponseResult(1,result);
    }

    @PostMapping("/ai/port_analysis")
    public ResponseResult AIPortAnalysis(@RequestBody List<HashMap<String, Object>> data)
    {
        String prompt= TextFileLoader.loadTextFile("texts/prompts/port_analysis_prompt.txt");
        String result = aiService.aiAssistWithPrompt(prompt, JSON.toJSONString(data));
        return new ResponseResult(1,result);
    }

}
