package com.tpp.threat_perception_platform.service.impl;

import com.alibaba.fastjson.JSON;
import com.tpp.threat_perception_platform.dao.HostMapper;
import com.tpp.threat_perception_platform.dao.SystemDetectMapper;
import com.tpp.threat_perception_platform.param.SystemDetectParam;
import com.tpp.threat_perception_platform.pojo.Host;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import com.tpp.threat_perception_platform.service.SystemDetectService;
import com.tpp.threat_perception_platform.utils.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class SystemDetectServiceImpl implements SystemDetectService {

    @Autowired
    private SystemDetectMapper systemDetectMapper;

    @Autowired
    private RabbitMQService rabbitMQService;
    @Autowired
    private HostMapper hostMapper;
    @Autowired
    private RedisCache redisCache;

    @Override
    public List<Map<String, Object>> getDetectedHosts() {
        List<Map<String, Object>> allHosts = systemDetectMapper.findDetectedHosts();
        Map<String, Map<String, Object>> uniqueHostsMap = new LinkedHashMap<>();

        // 遍历所有主机记录，根据 MAC 地址去重
        for (Map<String, Object> host : allHosts) {
            String macAddress = (String) host.get("macAddress");
            if (!uniqueHostsMap.containsKey(macAddress)) {
                uniqueHostsMap.put(macAddress, host);
            }
        }

        // 将去重后的主机记录转换为列表
        return new ArrayList<>(uniqueHostsMap.values());
    }

    @Override
    public List<Map<String, Object>> getSystemDetectByMac(String macAddress) {
        return systemDetectMapper.findSystemDetectByMac(macAddress);
    }

    @Override
    public ResponseResult systemDetect(SystemDetectParam param) {
        // 验证mac地址
        Host dbhost = hostMapper.selectByPrimaryKey(Long.valueOf(param.getHostId()));

        if (redisCache.getCacheObject("Heartbeat from " + dbhost.getMacAddress()) == null) {
            return new ResponseResult(0, "主机不在线！");
        }

        param.setType("system");
        param.setMacAddress(dbhost.getMacAddress());

        // 创建 info 对象
        Map<String, Object> info = new HashMap<>();
        info.put("type", "system"); // 固定为 system，也可以根据需求动态设置

        // 将 info 和 param 合并到一个新的对象中
        Map<String, Object> requestData = new HashMap<>();
        requestData.put("info", info);
        requestData.put("data", param); // 原始参数作为 data 字段发送

        String data = JSON.toJSONString(requestData);

        String rootingKey = "agentQueue" + dbhost.getMacAddress().replace(":", "");
        rabbitMQService.sendMessage("", rootingKey, JSON.toJSONString(param));

        return new ResponseResult(0, "探测任务发送成功！");
    }

    @Override
    public List<Map<String, Object>> getSystemDetectByMacAndSDetectId(String macAddress, Integer sDetectId) {
        return systemDetectMapper.findSystemDetectByMacAndSDetectId(macAddress, sDetectId);
    }

    @Override
    public List<Integer> getDetectionIdsByMac(String macAddress) {
        return systemDetectMapper.getDetectionIdsByMac(macAddress);
    }

    @Override
    public ResponseResult getSystemRiskTotal() {
        int total = systemDetectMapper.selectTotalCount();
        return new ResponseResult(0, "获取系统风险总数成功", total);
    }

}