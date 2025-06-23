package com.tpp.threat_perception_platform.service.impl;

import com.alibaba.fastjson.JSON;
import com.tpp.threat_perception_platform.dao.HostMapper;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.BaselineService;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import com.tpp.threat_perception_platform.utils.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class BaselineServiceImpl implements BaselineService {

    @Autowired
    private RabbitMQService rabbitMQService;

    @Autowired
    private HostMapper hostMapper;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private RedisCache redisCache;

    @Override
    public ResponseResult<Void> baselineDetect(Map<String, Object> data) {
        try {
            // 字段提取与校验
            if (!data.containsKey("id") || !data.containsKey("hostName") || !data.containsKey("macAddress")) {
                return new ResponseResult<>(1001, "字段缺失", null);
            }

            Integer id = Integer.parseInt(data.get("id").toString());
            String hostName = data.get("hostName").toString();
            String originMacAddress = data.get("macAddress").toString();
            String macAddress = originMacAddress.replace(":", "");

            // 检查主机是否在线
            if (redisCache.getCacheObject("Heartbeat from " + originMacAddress) == null) {
                return new ResponseResult<>(1002, "主机不在线！无法进行基线检测", null);
            }

            // 设置任务时间为当前时间
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String taskTime = sdf.format(new Date());

            // 构建消息体，使用LinkedHashMap保持顺序
            Map<String, Object> messageMap = new LinkedHashMap<>();
            messageMap.put("hostName", hostName);
            messageMap.put("macAddress", originMacAddress);
            messageMap.put("id", id);
            messageMap.put("taskTime", taskTime);
            messageMap.put("type", "baseline");
            messageMap.put("baselineTask", true);

            // 发送消息到队列
            String queueName = "agentQueue" + macAddress;
            rabbitMQService.sendMessage("", queueName, JSON.toJSONString(messageMap));

            return new ResponseResult<>(0, "基线检测任务已下发", null);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "基线检测任务下发失败：" + e.getMessage(), null);
        }
    }

    @Override
    public ResponseResult<Void> checkBaseline(Map<String, Object> data) {
        // 检查主机是否已进行过基线检测
        Integer hostId = (Integer) data.get("hostId");
        // TODO: 实现检查逻辑
        return new ResponseResult<>(0, "检查成功", null);
    }

    @Override
    public ResponseResult<Void> setDetectInterval(Map<String, Object> data) {
        try {
            // 构建定时检测消息，使用LinkedHashMap保持顺序
            Map<String, Object> messageMap = new LinkedHashMap<>();
            messageMap.put("hostName", data.get("hostName"));
            messageMap.put("macAddress", data.get("macAddress"));
            messageMap.put("id", data.get("hostId"));
            messageMap.put("taskTime", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
            messageMap.put("type", "baseline");
            messageMap.put("baselineTask", true);
            messageMap.put("interval", data.get("interval"));

            // 发送消息到队列
            String queueName = "agentQueue" + data.get("macAddress").toString().replace(":", "");
            rabbitMQService.sendMessage("", queueName, JSON.toJSONString(messageMap));

            return new ResponseResult<>(0, "定时检测设置成功", null);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult<>(500, "定时检测设置失败：" + e.getMessage(), null);
        }
    }

    @Override
    public ResponseResult<Map<String, Object>> getStatistics() {
        try {
            Map<String, Object> statistics = new HashMap<>();
            
            // 使用JDBC直接查询baseline_task表中的任务状态统计
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
} 