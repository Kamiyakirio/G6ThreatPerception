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
import java.util.TimeZone;
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

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_DATE_TIME.withZone(java.time.ZoneId.systemDefault());
    private static final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    {
        // 设置SimpleDateFormat使用系统默认时区
        DATE_FORMATTER.setTimeZone(TimeZone.getDefault());
    }
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
            String latestTime;

            // 先检查是否有日志记录
            String countSql = "SELECT COUNT(*) FROM log WHERE mac_address = ?";
            int count = jdbcTemplate.queryForObject(countSql, Integer.class, macAddress);

            if (count > 0) {
                // 有记录，查询log表中该MAC地址最新的日志记录时间
                String sql = "SELECT timestamp FROM log WHERE mac_address = ? ORDER BY timestamp DESC LIMIT 1";
                latestTime = jdbcTemplate.queryForObject(sql, String.class, macAddress);
            } else {
                // 无记录，使用当天0点作为起始时间
                Calendar calendar = Calendar.getInstance();
                calendar.set(Calendar.HOUR_OF_DAY, 0);
                calendar.set(Calendar.MINUTE, 0);
                calendar.set(Calendar.SECOND, 0);
                calendar.set(Calendar.MILLISECOND, 0);
                latestTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(calendar.getTime());
            }

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

            // 获取当前时间
            String currentTime = DATE_FORMATTER.format(new Date());
            String hostName = null;
            String formattedStartTime;

            // 先尝试从请求参数中获取主机名
            if (data.containsKey("hostName") && data.get("hostName") != null) {
                hostName = data.get("hostName").toString();
            }

            // 查询是否有历史日志记录
            try {
                String sql = "SELECT COUNT(*) FROM log WHERE mac_address = ?";
                int count = jdbcTemplate.queryForObject(sql, Integer.class, macAddress);

                if (count > 0) {
                    try {
                        // 有历史记录，使用最新日志时间作为起始时间
                        // 获取最新的记录，统一转换为标准日期时间格式进行比较
                        sql = "SELECT id, timestamp, host_name FROM log WHERE mac_address = ? " +
                            "ORDER BY CASE " +
                            "  WHEN timestamp LIKE '%T%' THEN STR_TO_DATE(REPLACE(timestamp, 'T', ' '), '%Y-%m-%d %H:%i:%s') " +
                            "  ELSE STR_TO_DATE(timestamp, '%Y-%m-%d %H:%i:%s') " +
                            "END DESC, id DESC LIMIT 1";
                        Map<String, Object> latestLog = jdbcTemplate.queryForMap(sql, macAddress);
                        Object timestampObj = latestLog.get("timestamp");
                        
                        // 如果日志中有主机名且我们还没有主机名，使用日志中的主机名
                        if (hostName == null && latestLog.get("host_name") != null && !latestLog.get("host_name").toString().isEmpty()) {
                            hostName = latestLog.get("host_name").toString();
                        }
                        
                        // 打印所有最近的日志记录用于调试
                        sql = "SELECT id, timestamp, host_name, " +
                            "CASE " +
                            "  WHEN timestamp LIKE '%T%' THEN STR_TO_DATE(REPLACE(timestamp, 'T', ' '), '%Y-%m-%d %H:%i:%s') " +
                            "  ELSE STR_TO_DATE(timestamp, '%Y-%m-%d %H:%i:%s') " +
                            "END as parsed_time " +
                            "FROM log WHERE mac_address = ? " +
                            "ORDER BY parsed_time DESC LIMIT 5";
                        List<Map<String, Object>> recentLogs = jdbcTemplate.queryForList(sql, macAddress);
                        for (Map<String, Object> log : recentLogs) {
                            System.out.println(String.format(
                                    "ID: %s, Timestamp: %s, Parsed Time: %s, Host Name: %s",
                                    log.get("id"), log.get("timestamp"), log.get("parsed_time"), log.get("host_name")
                            ));
                        }
                        
                        // 处理时间格式
                        String timestamp = timestampObj.toString();
                        if (timestamp.contains("T")) {
                            // 如果是ISO格式，转换为标准格式
                            LocalDateTime dateTime = LocalDateTime.parse(timestamp);
                            formattedStartTime = dateTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                        } else {
                            // 已经是标准格式
                            formattedStartTime = timestamp;
                        }
                        if (hostName != null) {
                            System.out.println("- Host: " + hostName);
                        }
                    } catch (Exception e) {
                        System.out.println("Error getting latest log: " + e.getMessage());
                        e.printStackTrace();
                        // 如果获取最新记录失败，使用默认值
                        Calendar calendar = Calendar.getInstance();
                        calendar.set(Calendar.HOUR_OF_DAY, 0);
                        calendar.set(Calendar.MINUTE, 0);
                        calendar.set(Calendar.SECOND, 0);
                        calendar.set(Calendar.MILLISECOND, 0);
                        formattedStartTime = DATE_FORMATTER.format(calendar.getTime());
                    }
                } else {
                    // 无历史记录，使用当天0点作为起始时间
                    Calendar calendar = Calendar.getInstance();
                    calendar.set(Calendar.HOUR_OF_DAY, 0);
                    calendar.set(Calendar.MINUTE, 0);
                    calendar.set(Calendar.SECOND, 0);
                    calendar.set(Calendar.MILLISECOND, 0);
                    formattedStartTime = DATE_FORMATTER.format(calendar.getTime());
                }
            } catch (Exception e) {
                e.printStackTrace();
                // 如果查询失败，使用默认值
                Calendar calendar = Calendar.getInstance();
                calendar.set(Calendar.HOUR_OF_DAY, 0);
                calendar.set(Calendar.MINUTE, 0);
                calendar.set(Calendar.SECOND, 0);
                calendar.set(Calendar.MILLISECOND, 0);
                formattedStartTime = DATE_FORMATTER.format(calendar.getTime());
            }

            // 如果还没有主机名，从Redis中获取
            if (hostName == null) {
                try {
                    String redisKey = "Heartbeat from " + macAddress;
                    Map<String, Object> heartbeatInfo = redisCache.getCacheMap(redisKey);
                    hostName = heartbeatInfo != null && heartbeatInfo.containsKey("hostName") 
                        ? heartbeatInfo.get("hostName").toString() 
                        : macAddress; // 如果获取不到主机名，使用MAC地址代替
                } catch (Exception e) {
                    hostName = macAddress; // 如果出错，使用MAC地址代替
                }
            }

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

            try {
                rabbitMQService.sendMessage("", queueName, JSON.toJSONString(messageMap));
            } catch (Exception e) {
                System.out.println("Error sending message to queue: " + e.getMessage());
                e.printStackTrace();
                return new ResponseResult(500, "发送同步消息失败：" + e.getMessage());
            }

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
                        executeSyncForTask(taskInfo, currentTime);

                        // 计算下次同步时间
                        Calendar calendar = Calendar.getInstance();
                        calendar.setTime(now);
                        calendar.add(Calendar.MINUTE, interval);
                        String newNextSyncTime = DATE_FORMATTER.format(calendar.getTime());
                        taskInfo.put("nextSyncTime", newNextSyncTime);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void executeSyncForTask(Map<String, Object> taskInfo, String currentTime) {
        try {
            String macAddress = (String) taskInfo.get("macAddress");
            String startTime;
            
            // 检查是否有历史记录
            try {
                String countSql = "SELECT COUNT(*) FROM log WHERE mac_address = ?";
                int count = jdbcTemplate.queryForObject(countSql, Integer.class, macAddress);
                
                if (count > 0) {
                    try {
                        // 有历史记录，获取数据库中最新的日志时间作为起始时间
                        String latestTimeSql = "SELECT timestamp FROM log WHERE mac_address = ? " +
                                "ORDER BY CASE " +
                                "  WHEN timestamp LIKE '%T%' THEN STR_TO_DATE(REPLACE(timestamp, 'T', ' '), '%Y-%m-%d %H:%i:%s') " +
                                "  ELSE STR_TO_DATE(timestamp, '%Y-%m-%d %H:%i:%s') " +
                                "END DESC, id DESC LIMIT 1";
                        startTime = jdbcTemplate.queryForObject(latestTimeSql, String.class, macAddress);
                        
                        // 如果时间包含'T'，转换格式
                        if (startTime.contains("T")) {
                            LocalDateTime dateTime = LocalDateTime.parse(startTime);
                            startTime = dateTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                        }
                        
                        // 更新任务信息中的起始时间，以便下次使用最新的时间
                        taskInfo.put("startTime", startTime);
                        
                        String recentLogsSql = "SELECT id, timestamp, host_name, " +
                                "CASE " +
                                "  WHEN timestamp LIKE '%T%' THEN STR_TO_DATE(REPLACE(timestamp, 'T', ' '), '%Y-%m-%d %H:%i:%s') " +
                                "  ELSE STR_TO_DATE(timestamp, '%Y-%m-%d %H:%i:%s') " +
                                "END as parsed_time " +
                                "FROM log WHERE mac_address = ? " +
                                "ORDER BY parsed_time DESC LIMIT 5";
                        List<Map<String, Object>> recentLogs = jdbcTemplate.queryForList(recentLogsSql, macAddress);
                        for (Map<String, Object> log : recentLogs) {
                            System.out.println(String.format(
                                    "ID: %s, Timestamp: %s, Parsed Time: %s, Host Name: %s",
                                    log.get("id"), log.get("timestamp"), log.get("parsed_time"), log.get("host_name")
                            ));
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        // 如果获取最新记录失败，使用任务中保存的起始时间
                        startTime = (String) taskInfo.get("startTime");
                    }
                } else {
                    // 无历史记录，使用当天0点作为起始时间
                    Calendar calendar = Calendar.getInstance();
                    calendar.set(Calendar.HOUR_OF_DAY, 0);
                    calendar.set(Calendar.MINUTE, 0);
                    calendar.set(Calendar.SECOND, 0);
                    calendar.set(Calendar.MILLISECOND, 0);
                    startTime = DATE_FORMATTER.format(calendar.getTime());
                    
                    // 更新任务信息中的起始时间
                    taskInfo.put("startTime", startTime);
                }
            } catch (Exception e) {
                e.printStackTrace();
                // 如果查询失败，使用任务中保存的起始时间
                startTime = (String) taskInfo.get("startTime");
            }
            
            // 发送到队列
            try {
                String queueName = "agentQueue" + macAddress.replace(":", "");
                Map<String, Object> messageMap = new LinkedHashMap<>();
                messageMap.put("hostName", taskInfo.get("hostName"));
                messageMap.put("macAddress", macAddress);
                messageMap.put("id", taskInfo.get("hostId"));
                messageMap.put("startTime", startTime);  // 使用最新的日志时间
                messageMap.put("endTime", currentTime);
                messageMap.put("type", "log");
                messageMap.put("detectLog", true);
                
                rabbitMQService.sendMessage("", queueName, JSON.toJSONString(messageMap));
                
                // 更新最后同步时间
                taskInfo.put("lastSyncTime", currentTime);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
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
    public ResponseResult getLogListById(Map<String, Object> params) {
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
            List<Log> logList = logMapper.selectLogListByLogScanId(Integer.parseInt(params.get("id").toString()));

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

    @Override
    public ResponseResult getSyncStatus(Map<String, Object> data) {
        try {
            String macAddress = data.get("macAddress").toString();
            Map<String, Object> taskInfo = syncTasks.get(macAddress);
            
            Map<String, Object> result = new HashMap<>();
            if (taskInfo != null) {
                result.put("enabled", true);
                result.put("interval", taskInfo.get("interval"));
            } else {
                result.put("enabled", false);
                result.put("interval", null);
            }
            
            return new ResponseResult(0, result);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult(500, "获取同步状态失败：" + e.getMessage());
        }
    }

    @Override
    public ResponseResult disableSync(Map<String, Object> data) {
        try {
            String macAddress = data.get("macAddress").toString();
            syncTasks.remove(macAddress);
            return new ResponseResult(0, "已停止定时同步");
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult(500, "停止定时同步失败：" + e.getMessage());
        }
    }

    @Override
    public ResponseResult deleteAll(Map<String, Object> data){
        Integer id=Integer.parseInt(data.get("id").toString());
        Integer logScanResult=jdbcTemplate.update("delete from log_scan where id=?", id);
        Integer logResult=jdbcTemplate.update("DELETE FROM log WHERE log_scan_id=?",id);
        if(logScanResult+logResult>=2){
            return new ResponseResult(0,"删除成功！");
        }
        else return new ResponseResult(1001,"删除失败！");
    }
}
