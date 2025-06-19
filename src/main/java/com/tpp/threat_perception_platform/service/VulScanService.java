package com.tpp.threat_perception_platform.service;

import com.tpp.threat_perception_platform.response.ResponseResult;

import java.util.HashMap;

public interface VulScanService {
    public ResponseResult createVulScanTask(HashMap<String,Object> data);

    public ResponseResult getScanResult(HashMap<String,Object> data);

    /**
     * 获取漏洞检测总数
     * @return 漏洞检测总数
     */
    public int getVulCount();
}
