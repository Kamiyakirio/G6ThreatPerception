package com.tpp.threat_perception_platform.controller;

import com.alibaba.fastjson.JSON;
import com.tpp.threat_perception_platform.asset.Account;
import com.tpp.threat_perception_platform.pojo.Log;
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

    @PostMapping("/ai/log_analysis")
    public ResponseResult AILogAnalysis(@RequestBody List<Log> logs)
    {
        String prompt= TextFileLoader.loadTextFile("texts/prompts/log_analysis_prompt.txt");
        String result = aiService.aiAssistWithPrompt(prompt, JSON.toJSONString(logs));
        return new ResponseResult(1,result);
    }

    @PostMapping("/ai/apprisk_analysis")
    public ResponseResult AIAppRiskAnalysis(@RequestBody List<Map<String, Object>> apprisks)
    {
        String prompt = TextFileLoader.loadTextFile("texts/prompts/apprisk_analysis_prompt.txt");
        String result = aiService.aiAssistWithPrompt(prompt, JSON.toJSONString(apprisks));
        return new ResponseResult(1, result);
    }

    @PostMapping("/ai/systemrisk_analysis")
    public ResponseResult AISystemRiskAnalysis(@RequestBody List<Map<String, Object>> risks)
    {
        String prompt = TextFileLoader.loadTextFile("texts/prompts/systemrisk_analysis_prompt.txt");
        String result = aiService.aiAssistWithPrompt(prompt, JSON.toJSONString(risks));
        return new ResponseResult(1, result);
    }

    @PostMapping("/ai/weakpwd_analysis")
    public ResponseResult AIWeakPwdAnalysis(@RequestBody List<Map<String, Object>> accounts)
    {
        String prompt = TextFileLoader.loadTextFile("texts/prompts/weakpwd_analysis_prompt.txt");
        String result = aiService.aiAssistWithPrompt(prompt, JSON.toJSONString(accounts));
        return new ResponseResult(1, result);
    }

    @PostMapping("/ai/vul_scan_analysis")
    public ResponseResult AIVulScanAnalysis(@RequestBody List<Map<String, Object>> vulscanResults)
    {
        String prompt = TextFileLoader.loadTextFile("texts/prompts/vul_scan_analysis_prompt.txt");
        String result = aiService.aiAssistWithPrompt(prompt, JSON.toJSONString(vulscanResults));
        return new ResponseResult(1, result);
    }

    @PostMapping("/ai/hotfix_analysis")
    public ResponseResult AIHotfixAnalysis(@RequestBody List<Map<String, Object>> hotfixResults)
    {
        String prompt = TextFileLoader.loadTextFile("texts/prompts/hotfix_analysis_prompt.txt");
        String result = aiService.aiAssistWithPrompt(prompt, JSON.toJSONString(hotfixResults));
        return new ResponseResult(1, result);
    }

}
