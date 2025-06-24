package com.tpp.threat_perception_platform.service;

import com.tpp.threat_perception_platform.response.ResponseResult;
import java.util.Map;
import java.util.List;
import com.tpp.threat_perception_platform.pojo.BaselineItemResult;

public interface BaselineService {
    ResponseResult<Void> baselineDetect(Map<String, Object> data);
    ResponseResult<Void> checkBaseline(Map<String, Object> data);
    ResponseResult<Void> setDetectInterval(Map<String, Object> data);
    ResponseResult<Map<String, Object>> getStatistics();
    List<BaselineItemResult> getBaselineDetail(String macAddress);
    void processBaselineData(Map<String, Object> data);
    
    /**
     * 获取基线检测列表数据
     * @param keywords 搜索关键词（可选，用于搜索主机名或MAC地址）
     * @param taskTime 任务时间（可选）
     * @param page 页码
     * @param limit 每页条数
     * @return 分页数据
     */
    ResponseResult<Map<String, Object>> getBaselineList(String keywords, String taskTime, Integer page, Integer limit);
} 