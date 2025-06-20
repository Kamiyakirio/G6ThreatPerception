package com.tpp.threat_perception_platform.service.impl;


import com.alibaba.fastjson.JSON;
import com.tpp.threat_perception_platform.dao.LogScanMapper;
import com.tpp.threat_perception_platform.pojo.LogScan;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.LogService;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import com.tpp.threat_perception_platform.utils.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Calendar;

import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.tpp.threat_perception_platform.dao.LogMapper;
import com.tpp.threat_perception_platform.pojo.Log;

import java.util.HashMap;
import java.util.List;

import com.tpp.threat_perception_platform.service.AIService;
import com.tpp.threat_perception_platform.utils.TextFileLoader;

@Service
@EnableScheduling
public class LogServiceImpl implements LogService {

    @Autowired
    private RabbitMQService rabbitMQService;
    @Autowired
    private RedisCache redisCache;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LogMapper logMapper;
    @Autowired
    private AIService aiService;
    @Autowired
    private LogScanMapper logScanMapper;

    // 存储定时任务信息
    private final ConcurrentHashMap<String, Map<String, Object>> syncTasks = new ConcurrentHashMap<>();

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_DATE_TIME;
    private static final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    @Override
    public ResponseResult logDetect(Map<String, Object> data) {
        try {
            // 字段提取与校验
            if (!data.containsKey("id") || !data.containsKey("hostName") || !data.containsKey("macAddress") || !data.containsKey("type")) {
                return new ResponseResult(1001, "字段缺失");
            }

            Integer id = Integer.parseInt(data.get("id").toString());
            String hostName = data.get("hostName").toString();
            String originMacAddress = data.get("macAddress").toString();
            String macAddress = data.get("macAddress").toString().replace(":", "");  // 移除MAC地址中的冒号
            String type = data.get("type").toString();
            String startTime = data.get("startTime").toString();
            String endTime = data.get("endTime").toString();

            // 构建消息体，使用LinkedHashMap保持顺序
            Map<String, Object> messageMap = new LinkedHashMap<>();
            messageMap.put("hostName", hostName);
            messageMap.put("macAddress", originMacAddress);
            messageMap.put("id", id);
            messageMap.put("startTime", startTime);
            messageMap.put("endTime", endTime);
            messageMap.put("type", "log");
            messageMap.put("detectLog", true);

            if (redisCache.getCacheObject("Heartbeat from " + originMacAddress) == null) {
                return new ResponseResult(1002, "主机不在线！无法进行日志审计");
            }

            // 发送消息（默认 exchange，队列名以 MAC 地址标识）
            String queueName = "agentQueue" + macAddress;  // 修改队列名称格式
            rabbitMQService.sendMessage("", queueName, JSON.toJSONString(messageMap));

            return new ResponseResult(0, "日志审计任务已发送");
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult(500, "发送失败：" + e.getMessage());
        }
    }

    @Override
    public ResponseResult checkLogs(Map<String, Object> data) {
        try {
            String macAddress = data.get("macAddress").toString();

            // 查询log表中是否有该MAC地址的记录
            String sql = "SELECT COUNT(*) FROM log WHERE mac_address = ?";
            int count = jdbcTemplate.queryForObject(sql, Integer.class, macAddress);

            System.out.println("Checking logs for MAC: " + macAddress + ", found " + count + " records");

            return new ResponseResult(0, count > 0);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult(500, "检查日志记录失败：" + e.getMessage());
        }
    }

    @Override
    public ResponseResult getLatestLogTime(Map<String, Object> data) {
        try {
            String macAddress = data.get("macAddress").toString();

            // 查询log表中该MAC地址最新的日志记录时间
            String sql = "SELECT timestamp FROM log WHERE mac_address = ? ORDER BY timestamp DESC LIMIT 1";
            String latestTime = jdbcTemplate.queryForObject(sql, String.class, macAddress);

            System.out.println("Getting latest log time for MAC: " + macAddress + ", time: " + latestTime);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("latestLogTime", latestTime);

            return new ResponseResult(0, result);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult(500, "获取最新日志时间失败：" + e.getMessage());
        }
    }

    @Override
    public ResponseResult setSyncInterval(Map<String, Object> data) {
        try {
            Integer hostId = Integer.parseInt(data.get("hostId").toString());
            String macAddress = data.get("macAddress").toString();
            Integer interval = Integer.parseInt(data.get("interval").toString());

            System.out.println("Setting sync interval - HostId: " + hostId + ", MAC: " + macAddress + ", Interval: " + interval);

            // 获取最新日志时间
            String sql = "SELECT timestamp, host_name FROM log WHERE mac_address = ? ORDER BY timestamp DESC LIMIT 1";
            Map<String, Object> latestLog = jdbcTemplate.queryForMap(sql, macAddress);
            String startTime = latestLog.get("timestamp").toString();
            String hostName = latestLog.get("host_name").toString();

            // 统一时间格式
            LocalDateTime startDateTime = LocalDateTime.parse(startTime, ISO_FORMATTER);
            String formattedStartTime = startDateTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

            System.out.println("Latest log time: " + formattedStartTime + ", Host name: " + hostName);

            // 获取当前时间
            String currentTime = DATE_FORMATTER.format(new Date());

            // 存储任务信息
            Map<String, Object> taskInfo = new LinkedHashMap<>();
            taskInfo.put("hostId", hostId);
            taskInfo.put("hostName", hostName);
            taskInfo.put("macAddress", macAddress);
            taskInfo.put("interval", interval);
            taskInfo.put("startTime", formattedStartTime);
            taskInfo.put("lastSyncTime", currentTime);

            // 计算下次同步时间（当前时间 + 间隔时间）
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.MINUTE, interval);
            String nextSyncTime = DATE_FORMATTER.format(calendar.getTime());
            taskInfo.put("nextSyncTime", nextSyncTime);

            // 使用MAC地址作为key存储任务
            syncTasks.put(macAddress, taskInfo);

            System.out.println("Task stored in syncTasks. Current tasks count: " + syncTasks.size());
            System.out.println("Task details: " + JSON.toJSONString(taskInfo));

            // 立即发送一次消息
            Map<String, Object> messageMap = new LinkedHashMap<>();
            messageMap.put("hostName", hostName);
            messageMap.put("macAddress", macAddress);
            messageMap.put("id", hostId);
            messageMap.put("startTime", formattedStartTime);
            messageMap.put("endTime", currentTime);
            messageMap.put("type", "log");
            messageMap.put("detectLog", true);

            // 发送到队列
            String queueName = "agentQueue" + macAddress.replace(":", "");
            System.out.println("Sending initial message to queue: " + queueName);
            System.out.println("Message content: " + JSON.toJSONString(messageMap));

            rabbitMQService.sendMessage("", queueName, JSON.toJSONString(messageMap));

            return new ResponseResult(0, "定时同步设置成功");
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult(500, "设置定时同步失败：" + e.getMessage());
        }
    }

    // 定时任务，每秒检查一次
    @Scheduled(fixedRate = 1000)
    public void executeSyncTasks() {
        try {
            String currentTime = DATE_FORMATTER.format(new Date());
            Date now = new Date();

            for (Map.Entry<String, Map<String, Object>> entry : syncTasks.entrySet()) {
                Map<String, Object> taskInfo = entry.getValue();
                String macAddress = entry.getKey();
                Integer interval = (Integer) taskInfo.get("interval");
                String nextSyncTime = (String) taskInfo.get("nextSyncTime");

                try {
                    // 检查是否到达下次同步时间
                    Date nextSync = DATE_FORMATTER.parse(nextSyncTime);
                    if (now.after(nextSync)) {
                        System.out.println("Time to sync for MAC: " + macAddress);
                        executeSyncForTask(taskInfo, currentTime);

                        // 计算下次同步时间
                        Calendar calendar = Calendar.getInstance();
                        calendar.setTime(now);
                        calendar.add(Calendar.MINUTE, interval);
                        String newNextSyncTime = DATE_FORMATTER.format(calendar.getTime());
                        taskInfo.put("nextSyncTime", newNextSyncTime);
                        System.out.println("Next sync time set to: " + newNextSyncTime);
                    }
                } catch (Exception e) {
                    System.out.println("Error checking sync time: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            System.out.println("Error in executeSyncTasks: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void executeSyncForTask(Map<String, Object> taskInfo, String currentTime) {
        try {
            String macAddress = (String) taskInfo.get("macAddress");
            System.out.println("Executing sync for MAC: " + macAddress);

            // 构建消息体
            Map<String, Object> messageMap = new LinkedHashMap<>();
            messageMap.put("hostName", taskInfo.get("hostName"));
            messageMap.put("macAddress", macAddress);
            messageMap.put("id", taskInfo.get("hostId"));
            messageMap.put("startTime", taskInfo.get("startTime"));
            messageMap.put("endTime", currentTime);
            messageMap.put("type", "log");
            messageMap.put("detectLog", true);

            // 发送到队列
            String queueName = "agentQueue" + macAddress.replace(":", "");
            System.out.println("Message content: " + JSON.toJSONString(messageMap));

            rabbitMQService.sendMessage("", queueName, JSON.toJSONString(messageMap));

            // 更新最后同步时间
            taskInfo.put("lastSyncTime", currentTime);
        } catch (Exception e) {
            System.out.println("Error in executeSyncForTask: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Override
    public ResponseResult getStatistics() {
        try {
            Map<String, Object> statistics = new HashMap<>();

            // 获取登录日志总数
            Long totalLogs = logMapper.selectTotalLogs();
            statistics.put("totalLogs", totalLogs != null ? totalLogs : 0);

            // 获取风险日志总数
            Long totalRisks = logMapper.selectTotalRiskLogs();
            statistics.put("totalRisks", totalRisks != null ? totalRisks : 0);

            // 获取风险等级分布
            List<Map<String, Object>> riskDistribution = logMapper.selectRiskDistribution();
            statistics.put("riskDistribution", riskDistribution);

            return new ResponseResult<>(200, "获取统计数据成功", statistics);
        } catch (Exception e) {
            return new ResponseResult<>(500, "获取统计数据失败: " + e.getMessage());
        }
    }

    @Override
    public ResponseResult getLogList(Map<String, Object> params) {
        try {
            // 设置分页参数
            Integer page = Integer.parseInt(params.get("page").toString());
            Integer limit = Integer.parseInt(params.get("limit").toString());
            if (page != null && limit != null) {
                PageHelper.startPage(page, limit);
            }

            // Convert riskLevel to Integer if it exists
            if (params.containsKey("riskLevel") && params.get("riskLevel") != null && !params.get("riskLevel").toString().isEmpty()) {
                params.put("riskLevel", Integer.parseInt(params.get("riskLevel").toString()));
            }

            // 查询日志列表
            List<Log> logList = logMapper.selectLogList(params);

            // 构建分页信息
            PageInfo<Log> pageInfo = new PageInfo<>(logList);

            return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
        } catch (Exception e) {
            return new ResponseResult<>(500, "获取日志列表失败: " + e.getMessage());
        }

    }

    @Override
    public ResponseResult getLogScanList(Map<String, Object> params) {
        try {
            // 设置分页参数
            Integer page = Integer.parseInt(params.get("page").toString());
            Integer limit = Integer.parseInt(params.get("limit").toString());
            if (page != null && limit != null) {
                PageHelper.startPage(page, limit);
            }

            // Convert riskLevel to Integer if it exists
            if (params.containsKey("riskLevel") && params.get("riskLevel") != null && !params.get("riskLevel").toString().isEmpty()) {
                params.put("riskLevel", Integer.parseInt(params.get("riskLevel").toString()));
            }

            // 查询日志列表
//            List<Log> logList = logMapper.selectLogList(params);
            String sql = "SELECT * from log_scan";
            List<Map<String, Object>> logScanList = jdbcTemplate.queryForList(sql);

            for(Map<String, Object> logScan : logScanList) {
                sql="SELECT COUNT(*) from log where risk_level = ? and log_scan_id = ?";
                logScan.put("lowLevelCount", jdbcTemplate.queryForObject(sql,Integer.class,1,logScan.get("id")));
                logScan.put("mediumLevelCount", jdbcTemplate.queryForObject(sql,Integer.class,2,logScan.get("id")));
                logScan.put("highLevelCount", jdbcTemplate.queryForObject(sql,Integer.class,3,logScan.get("id")));
                logScan.put("noLevelCount", jdbcTemplate.queryForObject(sql,Integer.class,0,logScan.get("id")));
            }

            // 构建分页信息
            PageInfo<Map<String, Object>> pageInfo = new PageInfo<>(logScanList);

            return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
        } catch (Exception e) {
            return new ResponseResult<>(500, "获取日志列表失败: " + e.getMessage());
        }
    }

    @Override
    public ResponseResult getLogDetail(Long logId) {
        try {
            Log log = logMapper.selectByPrimaryKey(logId);
            if (log == null) {
                return new ResponseResult<Log>(404, "日志不存在");
            }
            return new ResponseResult<Log>(200, log);
        } catch (Exception e) {
            return new ResponseResult<Log>(500, "获取日志详情失败: " + e.getMessage());
        }
    }

    @Override
    public ResponseResult getAccountLogStatistics() {
        List<Integer> accountEventIds = java.util.Arrays.asList(4720, 4722, 4723, 4724, 4726, 4728, 4738);
        Long total = logMapper.countByEventIds(accountEventIds, null); // 全部
        Long risk = logMapper.countByEventIds(accountEventIds, 1);     // 风险日志 risk_level > 0
        List<Map<String, Object>> riskDistribution = logMapper.selectRiskDistributionByEventIds(accountEventIds);
        java.util.Map<String, Object> data = new java.util.HashMap<>();
        data.put("totalLogs", total);
        data.put("totalRisks", risk);
        data.put("riskDistribution", riskDistribution);
        return new ResponseResult<>(200, "success", data);
    }

    @Override
    public ResponseResult getLoginLogStatistics() {
        List<Integer> loginEventIds = java.util.Arrays.asList(4624, 4625, 4634, 4647);
        Long total = logMapper.countByEventIds(loginEventIds, null); // 全部
        Long risk = logMapper.countByEventIds(loginEventIds, 1);     // 风险日志 risk_level > 0
        List<Map<String, Object>> riskDistribution = logMapper.selectRiskDistributionByEventIds(loginEventIds);
        java.util.Map<String, Object> data = new java.util.HashMap<>();
        data.put("totalLogs", total);
        data.put("totalRisks", risk);
        data.put("riskDistribution", riskDistribution);
        return new ResponseResult<>(200, "success", data);
    }

    @Override
    public ResponseResult getAllLogStatistics() {
        try {
            Long total = logMapper.selectTotalLogs();
            Long system = logMapper.countSystemLogs();
            Long security = logMapper.countSecurityLogs();
            Long risk = logMapper.selectTotalRiskLogs();
            java.util.Map<String, Object> data = new java.util.HashMap<>();
            data.put("totalLogs", total);
            data.put("systemLogs", system);
            data.put("securityLogs", security);
            data.put("riskLogs", risk);
            return new ResponseResult<>(200, "success", data);
        } catch (Exception e) {
            return new ResponseResult<>(500, "获取日志统计数据失败: " + e.getMessage());
        }
    }

    @Override
    public ResponseResult analyzeLogsWithAI(List<Log> logs) {
        try {
            if (logs == null || logs.isEmpty()) {
                return new ResponseResult<>(400, "日志数据为空");
            }
            // 调用AI服务分析日志
            String prompt = TextFileLoader.loadTextFile("texts/prompts/log_analysis_prompt.txt");
            String aiResult = aiService.aiAssistWithPrompt(prompt, JSON.toJSONString(logs));
            if (aiResult != null) {
                // 将AI分析结果存储到每条日志记录的ai_result字段中
                for (Log log : logs) {
                    if (log.getLogId() != null) {
                        Log updateLog = new Log();
                        updateLog.setLogId(log.getLogId());
                        updateLog.setAiResult(aiResult);
                        logMapper.updateByPrimaryKeySelective(updateLog);
                    }
                }
                // 直接将AI分析内容作为msg返回
                return new ResponseResult<>(200, aiResult);
            } else {
                return new ResponseResult<>(500, "AI分析失败");
            }
        } catch (Exception e) {
            return new ResponseResult<>(500, "AI分析异常: " + e.getMessage());
        }
    }

    @Override
    public ResponseResult batchAnalyzeLogsWithAI(Map<String, Object> params) {
        try {
            // 根据参数查询日志记录
            List<Log> logs = logMapper.selectLogList(params);

            if (logs == null || logs.isEmpty()) {
                return new ResponseResult<>(400, "未找到符合条件的日志记录");
            }

            // 调用AI分析
            return analyzeLogsWithAI(logs);

        } catch (Exception e) {
            return new ResponseResult<>(500, "批量AI分析异常: " + e.getMessage());
        }
    }

}
