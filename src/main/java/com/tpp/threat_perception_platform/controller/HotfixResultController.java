package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.pojo.HotfixResult;
import com.tpp.threat_perception_platform.service.HotfixResultService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/hotfix")
public class HotfixResultController {

    @Autowired
    private HotfixResultService hotfixResultService;

    @GetMapping("/list")
    public Map<String, Object> list(
            @RequestParam(value = "hostId", required = false) String hostId,
            @RequestParam(value = "page", defaultValue = "1") Integer page,
            @RequestParam(value = "limit", defaultValue = "10") Integer limit) {
        
        // 计算偏移量
        int offset = (page - 1) * limit;
        
        // 获取分组后的数据
        List<Map<String, Object>> list = hotfixResultService.getGroupedPageList(hostId, offset, limit);
        int count = hotfixResultService.getGroupedTotalCount(hostId);
        
        Map<String, Object> result = new HashMap<>();
        result.put("code", 0);
        result.put("msg", "");
        result.put("count", count);
        result.put("data", list);
        
        return result;
    }
} 