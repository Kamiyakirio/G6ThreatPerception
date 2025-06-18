package com.tpp.threat_perception_platform.service;

import com.tpp.threat_perception_platform.response.ResponseResult;
import java.util.Map;

public interface LogService {
    ResponseResult logDetect(Map<String, Object> data);
    
    // 检查是否有日志记录
    ResponseResult checkLogs(Map<String, Object> data);
    
    // 获取最新日志时间
    ResponseResult getLatestLogTime(Map<String, Object> data);
    
    // 设置定时同步
    ResponseResult setSyncInterval(Map<String, Object> data);
}