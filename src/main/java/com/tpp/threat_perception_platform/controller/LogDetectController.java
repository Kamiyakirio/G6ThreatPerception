package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.pojo.Log;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.LogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import java.util.List;

@RestController
public class LogDetectController {

    @Autowired
    private LogService logService;

    @PostMapping("/log/log_detect")
    public ResponseResult logDetect(@RequestBody Map<String, Object> data) {
        return logService.logDetect(data);
    }

    @PostMapping("/log/check_logs")
    public ResponseResult checkLogs(@RequestBody Map<String, Object> data) {
        return logService.checkLogs(data);
    }

    @PostMapping("/log/get_latest_log_time")
    public ResponseResult getLatestLogTime(@RequestBody Map<String, Object> data) {
        return logService.getLatestLogTime(data);
    }

    @PostMapping("/log/set_sync_interval")
    public ResponseResult setSyncInterval(@RequestBody Map<String, Object> data) {
        return logService.setSyncInterval(data);
    }

    /**
     * 登录日志统计页面 - 与现有菜单兼容
     */
    @RequestMapping("/page/log/statistics")
    public String statisticsPage() {
        return "log/loginStatistics";
    }

    /**
     * 登录日志统计页面 - 备用路由
     */
    @RequestMapping("/log/statistics/page")
    public String statisticsPageAlt() {
        return "log/loginStatistics";
    }

    /**
     * 获取登录日志统计数据
     * @return 统计数据
     */
    @ResponseBody
    @RequestMapping("/log/statistics")
    public ResponseResult getStatistics() {
        return logService.getLoginLogStatistics();
    }

    /**
     * 获取登录日志列表 - 支持form格式请求
     * @param params 查询参数
     * @return 日志列表
     */
    @ResponseBody
    @RequestMapping(value = "/log/list", method = RequestMethod.POST)
    public ResponseResult getLogScanList(@RequestParam Map<String, Object> params) {
        String logType = (String) params.get("logType");
        if ("login".equals(logType)) {
            params.put("eventIds", java.util.Arrays.asList(4624, 4625, 4634, 4647));
        } else if ("account".equals(logType)) {
            params.put("eventIds", java.util.Arrays.asList(4720, 4722, 4723, 4724, 4726, 4728, 4738));
        }
        return logService.getLogList(params);
    }

    @ResponseBody
    @PostMapping("/log/listById")
    public ResponseResult getLogListById(@RequestParam Map<String, Object> params) {
        return logService.getLogListById(params);
    }

    @PostMapping("/log/scanlist")
    public ResponseResult getLogList(@RequestParam Map<String, Object> params) {
        String logType = (String) params.get("logType");
        if ("login".equals(logType)) {
            params.put("eventIds", java.util.Arrays.asList(4624, 4625, 4634, 4647));
        } else if ("account".equals(logType)) {
            params.put("eventIds", java.util.Arrays.asList(4720, 4722, 4723, 4724, 4726, 4728, 4738));
        }
        return logService.getLogScanList(params);
    }

    /**
     * 获取日志详情
     * @param logId 日志ID
     * @return 日志详情
     */
    @ResponseBody
    @RequestMapping("/log/detail/{logId}")
    public ResponseResult getLogDetail(@PathVariable Long logId) {
        return logService.getLogDetail(logId);
    }

    @ResponseBody
    @RequestMapping("/log/account/statistics")
    public ResponseResult getAccountLogStatistics() {
        return logService.getAccountLogStatistics();
    }

    @ResponseBody
    @RequestMapping("/log/all/statistics")
    public ResponseResult getAllLogStatistics() {
        return logService.getAllLogStatistics();
    }

    /**
     * AI分析日志数据
     * @param logs 日志列表
     * @return AI分析结果
     */
    @ResponseBody
    @RequestMapping(value = "/log/ai/analysis", method = RequestMethod.POST)
    public ResponseResult analyzeLogsWithAI(@RequestBody List<Log> logs) {
        return logService.analyzeLogsWithAI(logs);
    }

    /**
     * 批量AI分析日志数据（根据查询条件）
     * @param params 查询参数
     * @return AI分析结果
     */
    @ResponseBody
    @RequestMapping(value = "/log/ai/batch-analysis", method = RequestMethod.POST)
    public ResponseResult batchAnalyzeLogsWithAI(@RequestBody Map<String, Object> params) {
        return logService.batchAnalyzeLogsWithAI(params);
    }

    /**
     * 获取日志同步状态
     */
    @PostMapping("/log/get_sync_status")
    public ResponseResult getSyncStatus(@RequestBody Map<String, Object> data) {
        return logService.getSyncStatus(data);
    }

    /**
     * 禁用日志同步
     */
    @PostMapping("/log/disable_sync")
    public ResponseResult disableSync(@RequestBody Map<String, Object> data) {
        return logService.disableSync(data);
    }
}
