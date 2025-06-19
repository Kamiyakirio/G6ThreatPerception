package com.tpp.threat_perception_platform.service;

import com.tpp.threat_perception_platform.response.ResponseResult;
import java.util.HashMap;

public interface AppRiskService {
    ResponseResult triggerAppRiskDetect(String macAddress);
    ResponseResult getAppRiskResults(String macAddress, Integer page, Integer limit);
    ResponseResult checkDetectionStatus(String macAddress);
    ResponseResult getAppRiskTotal();
} 