package com.tpp.threat_perception_platform.service.impl;

import com.alibaba.fastjson.JSON;
import com.tpp.threat_perception_platform.dao.VulScanMapper;
import com.tpp.threat_perception_platform.dao.VulnerabilityMapper;
import com.tpp.threat_perception_platform.pojo.VulScan;
import com.tpp.threat_perception_platform.pojo.Vulnerability;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import com.tpp.threat_perception_platform.service.VulScanService;
import com.tpp.threat_perception_platform.utils.RedisCache;
import io.lettuce.core.RedisClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@Service
public class VulScanServiceImpl implements VulScanService {

    @Autowired
    private RabbitMQService rabbitMQService;

    @Autowired
    private VulnerabilityMapper vulnerabilityMapper;

    @Autowired
    private VulScanMapper vulScanMapper;

    @Autowired
    private RedisCache redisCache;

    @Override
    public ResponseResult createVulScanTask(HashMap<String, Object> data) {
        HashMap<String, Object> resultData = new HashMap<>();
        HashMap<String, Object> scanOptions = new HashMap<>();
        HashMap<String, Object> dataData = (HashMap<String, Object>) data.get("data");

        // 校验数据
        if (dataData == null || dataData.get("macAddress") == null || dataData.get("hostName") == null || dataData.get("id") == null) {
            return new ResponseResult(1001, "参数错误!");
        }

        if (redisCache.getCacheObject("Heartbeat from " + dataData.get("macAddress")) == null) {
            return new ResponseResult(1002, "主机不在线！");
        }

        resultData.put("macAddress", dataData.get("macAddress"));
        resultData.put("hostName", dataData.get("hostName"));
        resultData.put("id", dataData.get("id"));

        resultData.put("type", "vulnerability");

        scanOptions.put("scanWeb", Integer.parseInt(data.get("scanWeb").toString()) != 0);
        scanOptions.put("scanSql", Integer.parseInt(data.get("scanSql").toString()) != 0);
        scanOptions.put("scanOthers", Integer.parseInt(data.get("scanOthers").toString()) != 0);

        resultData.put("scanOptions", scanOptions);


        List<Vulnerability> vulnerabilities = vulnerabilityMapper.selectVulnerability();
        resultData.put("vulnerabilities", vulnerabilities);

        rabbitMQService.sendMessage("", "agentQueue" + dataData.get("macAddress").toString().replace(":", ""), JSON.toJSONString(resultData));
        return new ResponseResult(0, "任务已发送，请等待扫描完成");
    }

    @Override
    public ResponseResult getScanResult(HashMap<String, Object> data) {
        List<VulScan> scanResult = vulScanMapper.selectAllByMacAddress(data.get("macAddress").toString());
        ArrayList<HashMap<String,Object>> resultData = new ArrayList<>();
        HashMap<String, Object> result = new HashMap<>();

        for (VulScan vulScan : scanResult) {
            Vulnerability vulnerability = vulnerabilityMapper.selectByPrimaryKey((long)vulScan.getVulId());
            HashMap<String, Object> resultObject = new HashMap<>();
            resultObject.put("id", vulScan.getId());
            resultObject.put("vulName",vulnerability.getName());
            resultObject.put("vulDesc",vulnerability.getDesc());
            resultObject.put("resultDesc",vulScan.getResultDesc());
            resultObject.put("time",vulScan.getTime());

            resultData.add(resultObject);
        }
        result.put("data", resultData);
        return new ResponseResult(0, resultData);
    }
}
