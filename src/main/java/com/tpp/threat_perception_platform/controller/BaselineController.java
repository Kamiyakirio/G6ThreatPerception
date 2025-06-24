package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.pojo.BaselineItemResult;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.BaselineService;
import com.tpp.threat_perception_platform.dao.BaselineScanMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import com.tpp.threat_perception_platform.pojo.BaselineScan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.tpp.threat_perception_platform.dao.BaselineTaskMapper;
import com.tpp.threat_perception_platform.pojo.BaselineTask;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import java.text.SimpleDateFormat;
import java.util.*;

import com.alibaba.fastjson.JSON;
import com.tpp.threat_perception_platform.utils.RedisCache;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.scheduling.annotation.Scheduled;
import com.tpp.threat_perception_platform.pojo.BaselineScan;

@Controller
public class BaselineController {

    private static final Logger log = LoggerFactory.getLogger(BaselineController.class);

    @Autowired
    private BaselineService baselineService;

    @Autowired
    private BaselineScanMapper baselineScanMapper;

    @Autowired
    private RabbitMQService rabbitMQService;

    @Autowired
    private BaselineTaskMapper baselineTaskMapper;

    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Autowired
    private RedisCache redisCache;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // 存储定时任务信息
    private final ConcurrentHashMap<String, Map<String, Object>> syncTasks = new ConcurrentHashMap<>();

    /**
     * 基线检测结果页面
     */
    @RequestMapping("/page/baseline/result")
    public String resultPage() {
        return "baseline/result";
    }

    /**
     * 基线检测页面
     */
    @RequestMapping("/page/baseline/detect")
    public String detectPage() {
        return "baseline/detect";
    }

    /**
     * 基线检测详情页面
     */
    @RequestMapping("/page/baseline/detail")
    public String detailPage(@RequestParam String macAddress) {
        return "baseline/detail";
    }

    /**
     * 执行基线检测
     */
    @ResponseBody
    @PostMapping("/api/baseline/detect")
    public ResponseResult<Void> baselineDetect(@RequestBody Map<String, Object> data) {
        return baselineService.baselineDetect(data);
    }

    /**
     * 获取基线检测统计信息
     */
    @ResponseBody
    @GetMapping("/api/baseline/statistics")
    public ResponseResult<Map<String, Object>> getBaselineStatistics() {
        return baselineService.getStatistics();
    }

    /**
     * 获取任务统计数据
     */
    @GetMapping("/baseline/statistics")
    @ResponseBody
    public ResponseResult<Map<String, Object>> getTaskStatistics() {
        try {
            Map<String, Object> statistics = new HashMap<>();

            // 查询已执行和未执行的任务数量
            Integer executedTasks = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM baseline_task WHERE task_status = 1", Integer.class);

            Integer unexecutedTasks = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM baseline_task WHERE task_status = 0", Integer.class);

            statistics.put("executedTasks", executedTasks != null ? executedTasks : 0);
            statistics.put("unexecutedTasks", unexecutedTasks != null ? unexecutedTasks : 0);

            return new ResponseResult<>(200, "获取统计数据成功", statistics);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "获取统计数据失败：" + e.getMessage(), null);
        }
    }

    /**
     * 获取基线检测列表
     */
    @ResponseBody
    @PostMapping("/api/baseline/list")
    public ResponseResult<Map<String, Object>> getBaselineList(@RequestParam(required = false) String macAddress,
                                                             @RequestParam(required = false) String taskTime,
                                                             @RequestParam(defaultValue = "1") Integer page,
                                                             @RequestParam(defaultValue = "10") Integer limit) {
        return baselineService.getBaselineList(macAddress, taskTime, page, limit);
    }

    /**
     * 获取基线检测详情
     */
    @ResponseBody
    @GetMapping("/api/baseline/detail")
    public ResponseResult<List<BaselineItemResult>> getBaselineDetail(@RequestParam String macAddress) {
        try {
            if (macAddress == null || macAddress.trim().isEmpty()) {
                return new ResponseResult<>(1001, "MAC地址不能为空", new ArrayList<>());
            }

            // 检查是否存在基线检测记录
            List<BaselineScan> scans = baselineScanMapper.selectByMacAddress(macAddress);
            if (scans == null || scans.isEmpty()) {
                return new ResponseResult<>(1002, "未找到该主机的基线检测记录，请先进行基线检测", new ArrayList<>());
            }

            // 获取基线检测详情
        List<BaselineItemResult> details = baselineService.getBaselineDetail(macAddress);

            // 即使列表为空也返回，让前端显示"未检测"状态
        return new ResponseResult<>(0, "获取成功", details);

        } catch (Exception e) {
            log.error("获取基线检测详情失败: {}", e.getMessage(), e);
            return new ResponseResult<>(500, "获取基线检测详情失败：" + e.getMessage(), new ArrayList<>());
        }
    }

    /**
     * 设置定时检测间隔
     */
    @PostMapping("/api/baseline/interval")
    @ResponseBody
    public ResponseResult<Void> setDetectInterval(@RequestBody Map<String, Object> data) {
        return baselineService.setDetectInterval(data);
    }

    /**
     * 设置定时检测间隔
     */
    @PostMapping("/baseline/set_detect_interval")
    @ResponseBody
    public ResponseResult<Void> setDetectIntervalForTask(@RequestBody Map<String, Object> data) {
        try {
            Integer id = Integer.parseInt(data.get("id").toString());
            String macAddress = (String) data.get("macAddress");
            Integer interval = Integer.parseInt(data.get("interval").toString());

            System.out.println("设置定时下发 - ID: " + id + ", MAC: " + macAddress + ", 间隔: " + interval + "小时");

            // 查询任务信息
            BaselineTask task = baselineTaskMapper.selectById(id);
            if (task == null) {
                return new ResponseResult<>(1, "任务不存在", null);
            }

            // 获取当前时间
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String currentTime = dateFormat.format(new Date());

            // 存储任务信息
            Map<String, Object> taskInfo = new LinkedHashMap<>();
            taskInfo.put("id", id);
            taskInfo.put("hostName", task.getHostName());
            taskInfo.put("macAddress", macAddress);
            taskInfo.put("interval", interval);
            taskInfo.put("lastSyncTime", currentTime);

            // 计算下次同步时间（当前时间 + 间隔时间）
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.HOUR, interval); // 使用小时作为单位
            String nextSyncTime = dateFormat.format(calendar.getTime());
            taskInfo.put("nextSyncTime", nextSyncTime);

            // 使用MAC地址作为key存储任务
            syncTasks.put(macAddress, taskInfo);

            System.out.println("定时任务已存储. 当前任务数量: " + syncTasks.size());
            System.out.println("任务详情: " + JSON.toJSONString(taskInfo));

            // 立即发送一次消息
            Map<String, Object> messageMap = new LinkedHashMap<>();
            messageMap.put("hostName", task.getHostName());
            messageMap.put("macAddress", macAddress);
            messageMap.put("id", id);
            messageMap.put("taskTime", dateFormat.format(task.getTaskTime()));
            messageMap.put("type", "baseline");
            messageMap.put("baselineTask", true);

            // 发送到队列
            String queueName = "agentQueue" + macAddress.replace(":", "");
            System.out.println("发送初始消息到队列: " + queueName);
            System.out.println("消息内容: " + JSON.toJSONString(messageMap));

            rabbitMQService.sendMessage("", queueName, JSON.toJSONString(messageMap));

            return new ResponseResult<>(0, "定时下发设置成功", null);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "设置定时下发失败: " + e.getMessage(), null);
        }
    }

    /**
     * 执行基线修复
     */
    @ResponseBody
    @PostMapping("/api/baseline/reinforce")
    public ResponseResult<Void> baselineReinforce(@RequestBody Map<String, Object> data) {
        try {
            // 验证必要参数
            if (!data.containsKey("macAddress") || !data.containsKey("hostName")) {
                return new ResponseResult<>(1001, "缺少必要参数", null);
            }

            // 构建agent队列名称 (使用不带冒号的MAC地址作为队列名)
            String macAddress = data.get("macAddress").toString();
            String queueName = "agentQueue" + macAddress.replace(":", "");

            // 发送消息到RabbitMQ (保持消息中的MAC地址带有冒号)
            String message = new ObjectMapper().writeValueAsString(data);
            rabbitMQService.sendMessage("", queueName, message);

            return new ResponseResult<>(0, "基线修复指令已发送", null);
        } catch (Exception e) {
            log.error("发送基线修复指令失败: {}", e.getMessage(), e);
            return new ResponseResult<>(500, "发送基线修复指令失败: " + e.getMessage(), null);
        }
    }

    /**
     * 获取修复详情
     */
    @ResponseBody
    @GetMapping("/api/baseline/repair-detail")
    public ResponseResult<Map<String, Object>> getRepairDetail(@RequestParam String macAddress) {
        try {
            if (macAddress == null || macAddress.trim().isEmpty()) {
                return new ResponseResult<>(1001, "MAC地址不能为空", null);
            }

            // 获取基线检测详情
            List<BaselineItemResult> details = baselineService.getBaselineDetail(macAddress);

            // 分类处理
            List<Map<String, String>> supported = new ArrayList<>();
            List<Map<String, String>> unsupported = new ArrayList<>();

            // 系统访问配置项
            Map<String, String> passwordItems = new HashMap<>();
            passwordItems.put("MinimumPasswordAge", "0");
            passwordItems.put("MaximumPasswordAge", "42");
            passwordItems.put("MinimumPasswordLength", "0");
            passwordItems.put("PasswordComplexity", "0");
            passwordItems.put("PasswordHistorySize", "0");
            passwordItems.put("LockoutBadCount", "0");

            // 审计策略配置项
            Map<String, String> auditItems = new HashMap<>();
            auditItems.put("AuditSystemEvents", "0");
            auditItems.put("AuditLogonEvents", "0");
            auditItems.put("AuditObjectAccess", "0");
            auditItems.put("AuditPrivilegeUse", "0");
            auditItems.put("AuditPolicyChange", "0");
            auditItems.put("AuditAccountManage", "0");
            auditItems.put("AuditProcessTracking", "0");
            auditItems.put("AuditDSAccess", "0");
            auditItems.put("AuditAccountLogon", "0");

            // 遍历检测结果，更新配置项的实际值
            for (BaselineItemResult item : details) {
                Map<String, String> itemMap = new HashMap<>();
                itemMap.put("name", item.getName());
                itemMap.put("value", item.getActualValue());

                if (item.getType() != null) {
                    switch (item.getType()) {
                        case "system_access":
                            if (passwordItems.containsKey(item.getName())) {
                                supported.add(itemMap);
                            } else {
                                unsupported.add(itemMap);
                            }
                            break;
                        case "event_audit":
                            if (auditItems.containsKey(item.getName())) {
                                supported.add(itemMap);
                            } else {
                                unsupported.add(itemMap);
                            }
                            break;
                        case "privilege_rights":
                        case "system_security_option":
                            unsupported.add(itemMap);
                            break;
                    }
                }
            }

            // 如果没有检测到的项目，添加默认配置
            if (supported.isEmpty()) {
                // 添加密码策略默认项
                for (Map.Entry<String, String> entry : passwordItems.entrySet()) {
                    Map<String, String> item = new HashMap<>();
                    item.put("name", entry.getKey());
                    item.put("value", entry.getValue());
                    supported.add(item);
                }

                // 添加审计策略默认项
                for (Map.Entry<String, String> entry : auditItems.entrySet()) {
                    Map<String, String> item = new HashMap<>();
                    item.put("name", entry.getKey());
                    item.put("value", entry.getValue());
                    supported.add(item);
                }
            }

            Map<String, Object> result = new HashMap<>();
            result.put("supported", supported);
            result.put("unsupported", unsupported);

            return new ResponseResult<>(0, "获取成功", result);

        } catch (Exception e) {
            log.error("获取修复详情失败: {}", e.getMessage(), e);
            return new ResponseResult<>(500, "获取修复详情失败：" + e.getMessage(), null);
        }
    }

    /**
     * 判断是否支持远程修复
     */
    private boolean isRemoteRepairSupported(BaselineItemResult item) {
        // 根据项目类型判断是否支持远程修复
        String type = item.getType();
        if (type == null) {
            return false;
        }

        switch (type) {
            case "system_access":
            case "event_audit":
                return true;
            case "privilege_rights":
            case "system_security_option":
                // 对于这些类型，可能需要根据具体配置项来判断
                return item.getStatus() != null && item.getStatus() == 0;
            default:
                return false;
        }
    }

    /**
     * 获取热力图数据
     */
    @ResponseBody
    @GetMapping("/api/baseline/heatmap-data")
    public ResponseResult<List<List<Object>>> getHeatmapData() {
        try {
            List<List<Object>> heatmapData = new ArrayList<>();

            // 获取所有基线检测数据
            List<BaselineItemResult> allResults = new ArrayList<>();
            List<BaselineScan> scans = baselineScanMapper.selectPageList(null, null, 0, Integer.MAX_VALUE);

            for (BaselineScan scan : scans) {
                allResults.addAll(baselineService.getBaselineDetail(scan.getMacAddress()));
            }

            // 统计各类型的正常和异常数量
            Map<String, int[]> typeStats = new HashMap<>();
            typeStats.put("system_access", new int[2]);      // [正常数, 异常数]
            typeStats.put("event_audit", new int[2]);
            typeStats.put("privilege_rights", new int[2]);
            typeStats.put("system_security_option", new int[2]);

            for (BaselineItemResult result : allResults) {
                if (result.getType() != null && typeStats.containsKey(result.getType())) {
                    int[] stats = typeStats.get(result.getType());
                    if (result.getStatus() != null) {
                        stats[result.getStatus() == 1 ? 0 : 1]++;
                    }
                }
            }

            // 转换为热力图数据格式
            int xIndex = 0;
            for (String type : new String[]{"system_access", "event_audit", "privilege_rights", "system_security_option"}) {
                int[] stats = typeStats.get(type);
                // 添加正常数据点
                heatmapData.add(Arrays.asList(xIndex, 0, stats[0]));
                // 添加异常数据点
                heatmapData.add(Arrays.asList(xIndex, 1, stats[1]));
                xIndex++;
            }

            return new ResponseResult<>(0, "获取成功", heatmapData);
        } catch (Exception e) {
            log.error("获取热力图数据失败: {}", e.getMessage(), e);
            return new ResponseResult<>(500, "获取热力图数据失败：" + e.getMessage(), null);
        }
    }

    /**
     * 获取任务列表
     */
    @PostMapping("/baseline/tasks")
    @ResponseBody
    public ResponseResult<List<BaselineTask>> getTasks(@RequestBody Map<String, Object> param) {
        try {
            // 获取分页参数
            int page = param.containsKey("page") ? Integer.parseInt(param.get("page").toString()) : 1;
            int limit = param.containsKey("limit") ? Integer.parseInt(param.get("limit").toString()) : 10;

            // 设置分页
            PageHelper.startPage(page, limit);
            List<BaselineTask> tasks = baselineTaskMapper.findAll();
            PageInfo<BaselineTask> pageInfo = new PageInfo<>(tasks);

            return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "获取任务列表失败：" + e.getMessage(), null);
        }
    }

    /**
     * 检查基线状态
     */
    @PostMapping("/baseline/check_baseline")
    @ResponseBody
    public ResponseResult<Void> checkBaseline(@RequestBody Map<String, Object> data) {
        try {
            Integer id = Integer.parseInt(data.get("id").toString());

            // 检查任务是否存在
            BaselineTask task = baselineTaskMapper.selectById(id);
            if (task == null) {
                return new ResponseResult<>(1, "任务不存在", null);
            }

            // 检查任务是否已执行
            if (task.getTaskStatus() != 1) {
                return new ResponseResult<>(1, "该任务尚未执行基线检测", null);
            }

            return new ResponseResult<>(0, "任务已执行", null);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "检查基线状态失败: " + e.getMessage(), null);
        }
    }

    /**
     * 删除任务
     */
    @PostMapping("/baseline/delete")
    @ResponseBody
    public ResponseResult<Void> deleteTask(@RequestBody Map<String, Object> data) {
        try {
            Integer id = Integer.parseInt(data.get("id").toString());
            int result = baselineTaskMapper.deleteById(id);
            if (result > 0) {
                return new ResponseResult<>(0, "删除成功", null);
            } else {
                return new ResponseResult<>(1, "删除失败，任务不存在", null);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "删除失败：" + e.getMessage(), null);
        }
    }

    /**
     * 添加任务
     */
    @PostMapping("/baseline/add")
    @ResponseBody
    public ResponseResult<Void> addTask(@RequestBody Map<String, Object> data) {
        try {
            // 创建新的基线检测任务对象
            BaselineTask task = new BaselineTask();

            // 设置任务属性
            task.setTaskName(data.get("taskName").toString());
            task.setMacAddress(data.get("macAddress").toString());
            task.setHostName(data.get("hostName").toString());

            // 解析时间字符串
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            try {
                task.setTaskTime(dateFormat.parse(data.get("taskTime").toString()));
            } catch (Exception e) {
                // 如果解析失败，使用当前时间
                task.setTaskTime(new Date());
            }

            // 设置任务状态（0-未执行，1-已执行）
            task.setTaskStatus(0);

            // 保存任务
            baselineTaskMapper.insert(task);

            return new ResponseResult<>(0, "添加任务成功", null);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "添加任务失败：" + e.getMessage(), null);
        }
    }

    /**
     * 批量删除任务
     */
    @PostMapping("/batch_delete")
    @ResponseBody
    public ResponseResult<Void> batchDeleteTasks(@RequestBody Map<String, Object> data) {
        try {
            @SuppressWarnings("unchecked")
            List<Integer> ids = (List<Integer>) data.get("ids");
            if (ids == null || ids.isEmpty()) {
                return new ResponseResult<>(1, "未选择要删除的任务", null);
            }

            for (Integer id : ids) {
                baselineTaskMapper.deleteById(id);
            }

            return new ResponseResult<>(0, "批量删除成功", null);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "批量删除失败：" + e.getMessage(), null);
        }
    }

    /**
     * 任务编辑页面
     */
    @RequestMapping("/page/baseline/task_edit")
    public String taskEditPage() {
        return "baseline/task_edit";
    }

    @PostMapping("/baseline/deploy")
    @ResponseBody
    public ResponseResult<Void> deployTask(@RequestBody Map<String, Object> params) {
        try {
            Integer id = Integer.parseInt(params.get("id").toString());
            String macAddress = (String) params.get("macAddress");
            String queueName = (String) params.get("queueName");

            // 打印队列名称，用于调试
            System.out.println("使用队列名称: " + queueName);

            // 从数据库获取任务详情
            BaselineTask task = baselineTaskMapper.selectById(id);
            if (task == null) {
                return new ResponseResult<>(1, "任务不存在", null);
            }

            // 检查主机是否在线
            if (redisCache.getCacheObject("Heartbeat from " + macAddress) == null) {
                return new ResponseResult<>(1002, "主机不在线！无法下发基线检测任务", null);
            }

            // 格式化日期为字符串形式
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String taskTimeStr = dateFormat.format(task.getTaskTime());

            // 构建消息内容，使用LinkedHashMap保持顺序
            Map<String, Object> message = new LinkedHashMap<>();
            message.put("hostName", task.getHostName());
            message.put("macAddress", macAddress);
            message.put("id", task.getId());
            message.put("taskTime", taskTimeStr);
            message.put("type", "baseline");
            message.put("baselineTask", true);

            // 打印消息内容到日志，用于调试
            System.out.println("发送消息到队列 " + queueName + ": " + JSON.toJSONString(message));

            // 发送消息到队列，参考LogServiceImpl中的实现
            rabbitMQService.sendMessage("", queueName, JSON.toJSONString(message));
            System.out.println("消息已发送");

            // 更新任务状态为已下发
            task.setTaskStatus(1); // 1表示已下发/已执行
            baselineTaskMapper.update(task);

            return new ResponseResult<>(0, "任务下发成功", null);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "任务下发失败: " + e.getMessage(), null);
        }
    }

    /**
     * 定时检查未执行的任务
     * 每分钟执行一次
     */
    @Scheduled(fixedRate = 60000)
    public void checkUnexecutedTasks() {
        try {
            // 查询所有未执行且已到执行时间的任务
            String sql = "SELECT * FROM baseline_task WHERE task_status = 0 AND task_time <= NOW()";
            List<Map<String, Object>> tasks = jdbcTemplate.queryForList(sql);

            for (Map<String, Object> task : tasks) {
                try {
                    String macAddress = task.get("mac_address").toString();

                    // 检查主机是否在线
                    if (redisCache.getCacheObject("Heartbeat from " + macAddress) == null) {
                        System.out.println("主机离线，无法执行任务：" + task.get("id") + ", MAC: " + macAddress);
                        continue;
                    }

                    // 构建消息内容
                    Map<String, Object> messageMap = new LinkedHashMap<>();
                    messageMap.put("hostName", task.get("host_name"));
                    messageMap.put("macAddress", macAddress);
                    messageMap.put("id", task.get("id"));

                    // 处理任务时间
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                    String taskTimeStr;
                    Object taskTimeObj = task.get("task_time");

                    if (taskTimeObj instanceof java.sql.Timestamp) {
                        taskTimeStr = sdf.format(new Date(((java.sql.Timestamp) taskTimeObj).getTime()));
                    } else if (taskTimeObj instanceof java.util.Date) {
                        taskTimeStr = sdf.format(taskTimeObj);
                    } else if (taskTimeObj instanceof String) {
                        taskTimeStr = (String) taskTimeObj;
                    } else {
                        // 如果是其他类型，尝试转换为字符串
                        taskTimeStr = taskTimeObj.toString();
                    }

                    messageMap.put("taskTime", taskTimeStr);
                    messageMap.put("type", "baseline");
                    messageMap.put("baselineTask", true);

                    // 发送到队列
                    String queueName = "agentQueue" + macAddress.replace(":", "");
                    System.out.println("自动执行任务，发送到队列: " + queueName);
                    System.out.println("消息内容: " + JSON.toJSONString(messageMap));

                    rabbitMQService.sendMessage("", queueName, JSON.toJSONString(messageMap));

                    // 更新任务状态为已执行
                    String updateSql = "UPDATE baseline_task SET task_status = 1, update_time = NOW() WHERE id = ?";
                    jdbcTemplate.update(updateSql, task.get("id"));

                    System.out.println("成功执行任务：" + task.get("id"));
                } catch (Exception e) {
                    System.out.println("执行任务失败：" + task.get("id") + ", 错误：" + e.getMessage());
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            System.out.println("检查未执行任务时出错：" + e.getMessage());
            e.printStackTrace();
        }
    }


    /**
     * 规则添加页面
     */
    @RequestMapping("/page/baseline/rule/add")
    public String ruleAddPage() {
        return "baseline/rule/add";
    }

    /**
     * 获取规则列表
     */
    @PostMapping("/baseline/rules")
    @ResponseBody
    public ResponseResult<List<Map<String, Object>>> getRules(@RequestBody Map<String, Object> params) {
        try {
            // 获取分页参数
            int page = params.containsKey("page") ? Integer.parseInt(params.get("page").toString()) : 1;
            int limit = params.containsKey("limit") ? Integer.parseInt(params.get("limit").toString()) : 10;

            // 计算偏移量
            int offset = (page - 1) * limit;

            // 查询规则列表
            List<Map<String, Object>> rules = jdbcTemplate.queryForList(
                "SELECT * FROM baseline_rule LIMIT ? OFFSET ?",
                limit, offset
            );

            // 查询总数
            Integer total = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM baseline_rule",
                Integer.class
            );

            // 转换规则数据
            List<Map<String, Object>> result = new ArrayList<>();
            for (Map<String, Object> rule : rules) {
                Map<String, Object> item = new HashMap<>();
                item.put("id", rule.get("id"));
                item.put("name", rule.get("name"));
                item.put("description", rule.get("description"));
                result.add(item);
            }

            return new ResponseResult<>(total != null ? total : 0, result);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "获取规则列表失败：" + e.getMessage(), null);
        }
    }

    /**
     * 添加规则
     */
    @PostMapping("/baseline/rule/add")
    @ResponseBody
    public ResponseResult<Void> addRule(@RequestBody Map<String, Object> params) {
        try {
            String name = params.get("name").toString();
            String description = params.get("description").toString();

            // 插入规则
            jdbcTemplate.update(
                "INSERT INTO baseline_rule (name, description) VALUES (?, ?)",
                name, description
            );

            return new ResponseResult<>(0, "添加规则成功", null);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "添加规则失败：" + e.getMessage(), null);
        }
    }

    /**
     * 删除规则
     */
    @PostMapping("/baseline/rule/delete")
    @ResponseBody
    public ResponseResult<Void> deleteRule(@RequestBody Map<String, Object> params) {
        try {
            Integer id = Integer.parseInt(params.get("id").toString());

            // 删除规则
            int result = jdbcTemplate.update(
                "DELETE FROM baseline_rule WHERE id = ?",
                id
            );

            if (result > 0) {
                return new ResponseResult<>(0, "删除规则成功", null);
            } else {
                return new ResponseResult<>(1, "规则不存在", null);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "删除规则失败：" + e.getMessage(), null);
        }
    }

@PostMapping("/baseline/rule/batch_delete")
    @ResponseBody
    public ResponseResult<Void> batchDeleteRules(@RequestBody Map<String, Object> params) {
        try {
            @SuppressWarnings("unchecked")
            List<Object> ruleIds = (List<Object>) params.get("ruleIds");

            if (ruleIds == null || ruleIds.isEmpty()) {
                return new ResponseResult<>(1, "未提供规则ID");
            }

            // 构建SQL语句
            java.lang.StringBuilder sql = new java.lang.StringBuilder("DELETE FROM baseline_rule WHERE rule_id IN (");
            for (int i = 0; i < ruleIds.size(); i++) {
                sql.append("?");
                if (i < ruleIds.size() - 1) {
                    sql.append(",");
                }
            }
            sql.append(")");

            // 执行批量删除
            int result = jdbcTemplate.update(sql.toString(), ruleIds.toArray());

            if (result > 0) {
                return new ResponseResult<>(0, "成功删除" + result + "条规则");
            } else {
                return new ResponseResult<>(1, "删除失败，未找到匹配的规则");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "批量删除规则失败: " + e.getMessage());
        }
    }

    /**
     * 将下划线命名转换为驼峰命名
     */
    private String convertToCamelCase(String underscoreName) {
        java.lang.StringBuilder result = new java.lang.StringBuilder();
        String[] parts = underscoreName.split("_");

        result.append(parts[0].toLowerCase());

        for (int i = 1; i < parts.length; i++) {
            if (parts[i].length() > 0) {
                result.append(parts[i].substring(0, 1).toUpperCase());
                if (parts[i].length() > 1) {
                    result.append(parts[i].substring(1).toLowerCase());
                }
            }
        }

        return result.toString();
    }

      /**
     * 获取基线规则列表（包含设置值）
     */
    @PostMapping("/baseline/rules/settings")
    @ResponseBody
    public ResponseResult<List<Map<String, Object>>> getRulesWithSettings(@RequestBody(required = false) Map<String, Object> params) {
        try {
            // 获取分页参数
            int page = params != null && params.containsKey("page") ? Integer.parseInt(params.get("page").toString()) : 1;
            int limit = params != null && params.containsKey("limit") ? Integer.parseInt(params.get("limit").toString()) : 15;

            // 首先获取system_access表中的设置
            String sql1 = "SELECT * FROM system_access ORDER BY system_access_id DESC LIMIT 1";
            Map<String, Object> settings = jdbcTemplate.queryForMap(sql1);

            // 获取system_security_option表中的设置
            String sql2 = "SELECT * FROM system_security_option ORDER BY system_security_option_id DESC LIMIT 1";
            Map<String, Object> securitySettings = jdbcTemplate.queryForMap(sql2);

            // 获取event_audit表中的设置
            String sql3 = "SELECT * FROM event_audit ORDER BY event_audit_id DESC LIMIT 1";
            Map<String, Object> auditSettings = jdbcTemplate.queryForMap(sql3);

            // 获取privilege_rights表中的设置
            String sql4 = "SELECT * FROM privilege_rights ORDER BY privilege_rights_id DESC LIMIT 1";
            Map<String, Object> privilegeSettings = jdbcTemplate.queryForMap(sql4);

            // 构建规则列表
            List<Map<String, Object>> allRules = new ArrayList<>();

            // 密码策略规则
            allRules.add(createRule("1", "密码最小使用期限", "密码更改前必须使用的最短天数",
                    Collections.singletonMap("minimum_password_age", settings.get("minimum_password_age"))));
            allRules.add(createRule("2", "密码最大使用期限", "密码必须更改前的最大天数",
                    Collections.singletonMap("maximum_password_age", settings.get("maximum_password_age"))));
            allRules.add(createRule("3", "密码最小长度", "密码必须包含的最少字符数",
                    Collections.singletonMap("minimum_password_length", settings.get("minimum_password_length"))));
            allRules.add(createRule("4", "密码复杂性要求", "密码是否必须包含多种字符类型",
                    Collections.singletonMap("password_complexity", settings.get("password_complexity"))));
            allRules.add(createRule("5", "密码历史记录大小", "防止重复使用最近使用过的密码数量",
                    Collections.singletonMap("password_history_size", settings.get("password_history_size"))));
            allRules.add(createRule("6", "账户锁定阈值", "登录尝试失败次数后锁定账户",
                    Collections.singletonMap("lockout_bad_count", settings.get("lockout_bad_count"))));
            allRules.add(createRule("7", "登录修改密码要求", "是否需要登录才能更改密码",
                    Collections.singletonMap("require_logon_to_change_password", settings.get("require_logon_to_change_password"))));
            allRules.add(createRule("8", "强制注销超时", "是否在登录时间到期时强制注销用户",
                    Collections.singletonMap("force_logoff_when_hour_expire", settings.get("force_logoff_when_hour_expire"))));
            allRules.add(createRule("9", "管理员账户名称", "管理员账户的自定义名称",
                    Collections.singletonMap("new_administrator_name", settings.get("new_administrator_name"))));
            allRules.add(createRule("10", "来宾账户名称", "来宾账户的自定义名称",
                    Collections.singletonMap("new_guest_name", settings.get("new_guest_name"))));
            allRules.add(createRule("11", "明文密码禁用", "是否禁止使用明文密码",
                    Collections.singletonMap("clear_text_password", settings.get("clear_text_password"))));
            allRules.add(createRule("12", "LSA匿名查询", "是否允许LSA匿名名称查找",
                    Collections.singletonMap("LSA_anonymous_name_lookup", settings.get("LSA_anonymous_name_lookup"))));
            allRules.add(createRule("13", "管理员账户状态", "是否启用管理员账户",
                    Collections.singletonMap("enable_admin_account", settings.get("enable_admin_account"))));
            allRules.add(createRule("14", "来宾账户状态", "是否启用来宾账户",
                    Collections.singletonMap("enable_guest_account", settings.get("enable_guest_account"))));

            // 系统安全选项规则
            allRules.add(createRule("15", "LM哈希禁用", "是否禁止存储LM哈希",
                    Collections.singletonMap("no_LM_hash", securitySettings.get("no_LM_hash"))));
            allRules.add(createRule("16", "空密码限制", "是否限制空密码账户的使用",
                    Collections.singletonMap("limit_blank_password_use", securitySettings.get("limit_blank_password_use"))));
            allRules.add(createRule("17", "匿名访问限制", "是否限制匿名用户访问",
                    Collections.singletonMap("restrict_anonymous", securitySettings.get("restrict_anonymous"))));
            allRules.add(createRule("18", "显示最后用户名", "是否在登录界面显示最后登录的用户名",
                    Collections.singletonMap("dont_display_last_user_name", securitySettings.get("dont_display_last_user_name"))));
            allRules.add(createRule("19", "明文密码禁用", "是否禁止使用明文密码",
                    Collections.singletonMap("enable_plain_text_password", securitySettings.get("enable_plain_text_password"))));
            allRules.add(createRule("20", "页面文件清理", "是否在关机时清理页面文件",
                    Collections.singletonMap("clear_page_file_at_shutdown", securitySettings.get("clear_page_file_at_shutdown"))));

            // 审计策略规则
            allRules.add(createRule("21", "系统事件审计", "是否审计系统事件",
                    Collections.singletonMap("audit_system_events", auditSettings.get("audit_system_events"))));
            allRules.add(createRule("22", "登录事件审计", "是否审计登录事件",
                    Collections.singletonMap("audit_logon_events", auditSettings.get("audit_logon_events"))));
            allRules.add(createRule("23", "对象访问审计", "是否审计对象访问",
                    Collections.singletonMap("audit_object_access", auditSettings.get("audit_object_access"))));
            allRules.add(createRule("24", "特权使用审计", "是否审计特权使用",
                    Collections.singletonMap("audit_privilege_use", auditSettings.get("audit_privilege_use"))));
            allRules.add(createRule("25", "策略更改审计", "是否审计策略更改",
                    Collections.singletonMap("audit_policy_change", auditSettings.get("audit_policy_change"))));
            allRules.add(createRule("26", "账户管理审计", "是否审计账户管理操作",
                    Collections.singletonMap("audit_account_manage", auditSettings.get("audit_account_manage"))));
            allRules.add(createRule("27", "进程追踪审计", "是否审计详细进程创建记录",
                    Collections.singletonMap("audit_process_tracking", auditSettings.get("audit_process_tracking"))));
            allRules.add(createRule("28", "目录服务访问审计", "是否审计目录服务访问",
                    Collections.singletonMap("audit_DS_access", auditSettings.get("audit_DS_access"))));
            allRules.add(createRule("29", "账户登录审计", "是否审计账户登录",
                    Collections.singletonMap("audit_account_logon", auditSettings.get("audit_account_logon"))));

            // 权限规则
            allRules.add(createRule("30", "分析单个进程权限", "允许分析单个进程的性能",
                    Collections.singletonMap("se_profile_single_process_privilege", privilegeSettings.get("se_profile_single_process_privilege"))));
            allRules.add(createRule("31", "远程关机权限", "允许从远程系统强制关机",
                    Collections.singletonMap("se_remote_shutdown_privilege", privilegeSettings.get("se_remote_shutdown_privilege"))));
            allRules.add(createRule("32", "关机权限", "允许关闭系统",
                    Collections.singletonMap("se_shutdown_privilege", privilegeSettings.get("se_shutdown_privilege"))));

            // 计算总记录数
            int total = allRules.size();

            // 计算分页
            int startIndex = (page - 1) * limit;
            int endIndex = Math.min(startIndex + limit, total);

            // 获取当前页的数据
            List<Map<String, Object>> pageRules = allRules.subList(startIndex, endIndex);

            // 返回分页结果
            ResponseResult<List<Map<String, Object>>> result = new ResponseResult<>(0, "获取成功", pageRules);
            result.setCount((long) total);
            return result;

        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(1, "获取失败: " + e.getMessage());
        }
    }

    /**
     * 创建规则对象
     */
    private Map<String, Object> createRule(String id, String name, String description, Map<String, Object> settings) {
        Map<String, Object> rule = new HashMap<>();
        rule.put("id", id);
        rule.put("name", name);
        rule.put("description", description);
        rule.put("settings", settings);
        return rule;
    }


    /**
     * 更新规则设置
     */
    @PostMapping("/baseline/rule/update_setting")
    @ResponseBody
    public ResponseResult<?> updateRuleSetting(@RequestBody Map<String, Object> params) {
        try {
            Integer ruleId = Integer.parseInt(params.get("rule_id").toString());
            @SuppressWarnings("unchecked")
            Map<String, Object> settings = (Map<String, Object>) params.get("settings");

            if (settings == null || settings.isEmpty()) {
                return new ResponseResult<>(1, "设置值不能为空");
            }

            // 创建规则ID到字段名的映射
            Map<Integer, Map<String, String>> ruleFieldMappings = new HashMap<>();

            // 系统访问设置映射
            Map<String, String> systemAccessFields = new HashMap<>();
            systemAccessFields.put("1", "minimum_password_age");
            systemAccessFields.put("2", "maximum_password_age");
            systemAccessFields.put("3", "minimum_password_length");
            systemAccessFields.put("4", "password_complexity");
            systemAccessFields.put("5", "password_history_size");
            systemAccessFields.put("6", "lockout_bad_count");
            systemAccessFields.put("7", "require_logon_to_change_password");
            systemAccessFields.put("8", "force_logoff_when_hour_expire");
            systemAccessFields.put("9", "new_administrator_name");
            systemAccessFields.put("10", "new_guest_name");
            systemAccessFields.put("11", "clear_text_password");
            systemAccessFields.put("12", "LSA_anonymous_name_lookup");
            systemAccessFields.put("13", "enable_admin_account");
            systemAccessFields.put("14", "enable_guest_account");
            ruleFieldMappings.put(1, systemAccessFields);

            // 系统安全选项映射
            Map<String, String> securityOptionFields = new HashMap<>();
            securityOptionFields.put("15", "no_LM_hash");
            securityOptionFields.put("16", "limit_blank_password_use");
            securityOptionFields.put("17", "restrict_anonymous");
            securityOptionFields.put("18", "dont_display_last_user_name");
            securityOptionFields.put("19", "enable_plain_text_password");
            securityOptionFields.put("20", "clear_page_file_at_shutdown");
            ruleFieldMappings.put(2, securityOptionFields);

            // 事件审计映射
            Map<String, String> eventAuditFields = new HashMap<>();
            eventAuditFields.put("21", "audit_system_events");
            eventAuditFields.put("22", "audit_logon_events");
            eventAuditFields.put("23", "audit_object_access");
            eventAuditFields.put("24", "audit_privilege_use");
            eventAuditFields.put("25", "audit_policy_change");
            eventAuditFields.put("26", "audit_account_manage");
            eventAuditFields.put("27", "audit_process_tracking");
            eventAuditFields.put("28", "audit_DS_access");
            eventAuditFields.put("29", "audit_account_logon");
            ruleFieldMappings.put(3, eventAuditFields);

            // 权限设置映射
            Map<String, String> privilegeFields = new HashMap<>();
            privilegeFields.put("30", "se_profile_single_process_privilege");
            privilegeFields.put("31", "se_remote_shutdown_privilege");
            privilegeFields.put("32", "se_shutdown_privilege");
            ruleFieldMappings.put(4, privilegeFields);

            // 获取第一个设置项的值
            Map.Entry<String, Object> firstSetting = settings.entrySet().iterator().next();
            Object fieldValue = firstSetting.getValue();

            // 确定要更新的表和字段
            String tableName;
            String fieldName = null;
            int tableType = 0;

            if (ruleId >= 1 && ruleId <= 14) {
                tableName = "system_access";
                tableType = 1;
            } else if (ruleId >= 15 && ruleId <= 20) {
                tableName = "system_security_option";
                tableType = 2;
            } else if (ruleId >= 21 && ruleId <= 29) {
                tableName = "event_audit";
                tableType = 3;
            } else if (ruleId >= 30 && ruleId <= 32) {
                tableName = "privilege_rights";
                tableType = 4;
            } else {
                return new ResponseResult<>(1, "无效的规则ID: " + ruleId);
            }

            // 获取对应的字段映射
            Map<String, String> fieldMapping = ruleFieldMappings.get(tableType);
            if (fieldMapping != null) {
                fieldName = fieldMapping.get(String.valueOf(ruleId));
            }

            if (fieldName == null) {
                return new ResponseResult<>(1, "无法确定要更新的字段");
            }

            // 处理二元值转换
            if (ruleId >= 21 && ruleId <= 29) {
                // 审计策略规则保持原值（0-3）
                if (fieldValue instanceof String) {
                    fieldValue = Integer.parseInt((String) fieldValue);
                }
            } else if (fieldValue instanceof String) {
                // 对于是/否类型的规则，转换为0/1
                if (fieldValue.equals("是")) {
                    fieldValue = 1;
                } else if (fieldValue.equals("否")) {
                    fieldValue = 0;
                }
            }

            // 构建更新SQL
            String sql = String.format("UPDATE %s SET %s = ? WHERE 1=1", tableName, fieldName);
            switch (tableType) {
                case 1:
                    sql += " ORDER BY system_access_id DESC LIMIT 1";
                    break;
                case 2:
                    sql += " ORDER BY system_security_option_id DESC LIMIT 1";
                    break;
                case 3:
                    sql += " ORDER BY event_audit_id DESC LIMIT 1";
                    break;
                case 4:
                    sql += " ORDER BY privilege_rights_id DESC LIMIT 1";
                    break;
            }

            System.out.println("执行的SQL: " + sql);
            System.out.println("参数值: " + fieldValue);
            System.out.println("参数类型: " + (fieldValue != null ? fieldValue.getClass().getName() : "null"));

            // 执行更新
            int result = jdbcTemplate.update(sql, fieldValue);

            if (result > 0) {
                return new ResponseResult<>(0, "更新成功");
            } else {
                return new ResponseResult<>(1, "更新失败：没有记录被更新");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(1, "更新失败：" + e.getMessage());
        }
    }}

