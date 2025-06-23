package com.tpp.threat_perception_platform.service;

import com.tpp.threat_perception_platform.response.ResponseResult;
import java.util.Map;

public interface BaselineService {
    ResponseResult<Void> baselineDetect(Map<String, Object> data);
    ResponseResult<Void> checkBaseline(Map<String, Object> data);
    ResponseResult<Void> setDetectInterval(Map<String, Object> data);
    ResponseResult<Map<String, Object>> getStatistics();
} 