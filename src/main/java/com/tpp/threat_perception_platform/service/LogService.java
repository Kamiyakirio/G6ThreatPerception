package com.tpp.threat_perception_platform.service;

import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.pojo.Log;

import java.util.List;
import java.util.Map;

public interface LogService {


    ResponseResult logDetect(Map<String, Object> data);
    
    // 检查是否有日志记录
    ResponseResult checkLogs(Map<String, Object> data);
    
    // 获取最新日志时间
    ResponseResult getLatestLogTime(Map<String, Object> data);
    
    // 设置定时同步
    ResponseResult setSyncInterval(Map<String, Object> data);

    /**
     * 获取登录日志统计数据
     * @return 统计数据
     */
    ResponseResult getStatistics();

    /**
     * 获取登录日志列表
     * @param params 查询参数
     * @return 日志列表
     */
    ResponseResult getLogList(Map<String, Object> params);

    ResponseResult getLogScanList(Map<String, Object> params);

    /**
     * 获取日志详情
     * @param logId 日志ID
     * @return 日志详情
     */
    ResponseResult getLogDetail(Long logId);

    /**
     * 获取账号变更日志统计数据（含风险等级分布）
     * @return 统计数据
     */
    ResponseResult getAccountLogStatistics();

    /**
     * 获取登录日志统计数据（含风险等级分布）
     *
     */
    ResponseResult getLoginLogStatistics();

    /**
     * 获取所有日志统计数据（总数、system、security、风险日志总数）
     */
    ResponseResult getAllLogStatistics();

    /**
     * AI分析日志数据
     * @param logs 日志列表
     * @return AI分析结果
     */
    ResponseResult analyzeLogsWithAI(List<Log> logs);

    /**
     * 批量AI分析日志数据（根据查询条件）
     * @param params 查询参数（如macAddress、hostName、时间范围等）
     * @return AI分析结果
     */
    ResponseResult batchAnalyzeLogsWithAI(Map<String, Object> params);

}