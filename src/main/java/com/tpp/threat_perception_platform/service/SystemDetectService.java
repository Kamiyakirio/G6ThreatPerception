package com.tpp.threat_perception_platform.service;

import com.tpp.threat_perception_platform.dao.SystemDetectMapper;
import com.tpp.threat_perception_platform.param.SystemDetectParam;
import com.tpp.threat_perception_platform.response.ResponseResult;

import java.util.List;
import java.util.Map;

public interface SystemDetectService {
    List<Map<String, Object>> getDetectedHosts();

    List<Map<String, Object>> getSystemDetectByMac(String macAddress);

    public ResponseResult systemDetect(SystemDetectParam param);



}
