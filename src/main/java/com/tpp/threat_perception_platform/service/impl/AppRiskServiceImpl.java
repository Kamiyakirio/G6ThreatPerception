package com.tpp.threat_perception_platform.service.impl;

import com.alibaba.fastjson.JSON;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.tpp.threat_perception_platform.dao.AppRiskResultMapper;
import com.tpp.threat_perception_platform.pojo.AppRiskResult;
import com.tpp.threat_perception_platform.pojo.Host;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.AppRiskService;
import com.tpp.threat_perception_platform.service.HostService;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import com.tpp.threat_perception_platform.utils.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class AppRiskServiceImpl implements AppRiskService {

    @Autowired
    private HostService hostService;

    @Autowired
    private RabbitMQService rabbitMQService;

    @Autowired
    private RedisCache redisCache;

    @Autowired
    private AppRiskResultMapper appRiskResultMapper;

    private static final String DETECTION_STATUS_KEY_PREFIX = "apprisk_detection_status:";
    private static final int DETECTION_TIMEOUT_MINUTES = 5; // 5分钟超时

    @Override
    public ResponseResult triggerAppRiskDetect(String macAddress) {
        try {
            // 根据MAC地址查找主机
            Host host = hostService.selectByMacAddress(macAddress);
            if (host == null) {
                return new ResponseResult(1001, "主机不存在！");
            }

            String originMacAddress = host.getMacAddress();
            String macAddressWithoutColons = originMacAddress.replace(":", "");

            // 检查主机是否在线
            if (redisCache.getCacheObject("Heartbeat from " + originMacAddress) == null) {
                return new ResponseResult(1002, "主机不在线，无法下发探测指令！");
            }

             // 构建发送给Agent的消息体
            HashMap<String, Object> infoMap = new HashMap<>();
            infoMap.put("id", host.getId());
            infoMap.put("hostName", host.getHostName());
            infoMap.put("macAddress", originMacAddress);
            infoMap.put("type", "apprisk");
            infoMap.put("targetHost", host.getIpAddress());
            infoMap.put("webBaseUrl", "http://" + host.getIpAddress() + ":8080");

            // 将info包装到外层消息中
            HashMap<String, Object> messageMap = new HashMap<>();
            messageMap.put("info", infoMap);
            messageMap.put("detectAppRisk", true);

            // 记录检测开始时间和状态
            String statusKey = DETECTION_STATUS_KEY_PREFIX + macAddress;
            HashMap<String, Object> status = new HashMap<>();
            status.put("startTime", new Date());
            status.put("completed", false);
            redisCache.setCacheObject(statusKey, status, DETECTION_TIMEOUT_MINUTES, TimeUnit.MINUTES);

            // 发送消息到Agent的专用队列
            rabbitMQService.sendMessage("", "agentQueue" + macAddressWithoutColons, JSON.toJSONString(messageMap));

            return new ResponseResult(0, "应用风险探测指令已成功下发！");

        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseResult(500, "下发应用风险探测指令失败: " + e.getMessage());
        }
    }

    @Override
    public ResponseResult checkDetectionStatus(String macAddress) {
        String statusKey = DETECTION_STATUS_KEY_PREFIX + macAddress;
        HashMap<String, Object> status = redisCache.getCacheObject(statusKey);
        
        // 首先检查是否有最新的检测结果
        List<AppRiskResult> latestResults = appRiskResultMapper.selectLatestByMacAddress(macAddress);
        if (latestResults != null && !latestResults.isEmpty()) {
            // 获取最新结果的检测时间
            Date latestDetectionTime = latestResults.get(0).getDetectedAt();
            
            // 如果status存在，比较时间来确定是否是新的检测结果
            if (status != null) {
                Date startTime = (Date) status.get("startTime");
                // 如果最新结果的时间晚于检测开始时间，说明检测已完成
                if (latestDetectionTime != null && startTime != null && 
                    latestDetectionTime.after(startTime)) {
                    // 更新状态为已完成
                    HashMap<String, Object> newStatus = new HashMap<>();
                    newStatus.put("completed", true);
                    newStatus.put("startTime", startTime);
                    redisCache.setCacheObject(statusKey, newStatus, DETECTION_TIMEOUT_MINUTES, TimeUnit.MINUTES);
                    return new ResponseResult(0, "检测已完成", newStatus);
                }
            } else {
                // 如果没有状态记录但有检测结果，也认为是完成的
                HashMap<String, Object> response = new HashMap<>();
                response.put("completed", true);
                return new ResponseResult(0, "检测已完成", response);
            }
        }
        
        // 如果有状态记录，返回当前状态
        if (status != null) {
            return new ResponseResult(0, "获取检测状态成功", status);
        }
        
        // 如果既没有状态也没有结果，返回未开始状态
        HashMap<String, Object> response = new HashMap<>();
        response.put("completed", false);
        return new ResponseResult(0, "检测尚未开始或已超时", response);
    }

    @Override
    public ResponseResult getAppRiskResults(String macAddress, Integer page, Integer limit) {
        PageHelper.startPage(page, limit);
        // 使用新的查询方法，只获取最新一次检测的结果
        List<AppRiskResult> results = appRiskResultMapper.selectLatestByMacAddress(macAddress);
        
        // 更新检测状态为已完成
        if (results != null && !results.isEmpty()) {
            String statusKey = DETECTION_STATUS_KEY_PREFIX + macAddress;
            HashMap<String, Object> status = new HashMap<>();
            status.put("completed", true);
            redisCache.setCacheObject(statusKey, status, DETECTION_TIMEOUT_MINUTES, TimeUnit.MINUTES);
        }

        PageInfo<AppRiskResult> pageInfo = new PageInfo<>(results);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }

    @Override
    public ResponseResult getAppRiskTotal() {
        int total = appRiskResultMapper.selectTotalCount();
        return new ResponseResult(0, "获取应用风险总数成功", total);
    }
}
