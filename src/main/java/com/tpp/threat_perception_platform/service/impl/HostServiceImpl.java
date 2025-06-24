package com.tpp.threat_perception_platform.service.impl;

import com.alibaba.fastjson.JSON;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.tpp.threat_perception_platform.dao.HostMapper;
import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.pojo.Host;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.HostService;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import com.tpp.threat_perception_platform.utils.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;

@Service
public class HostServiceImpl implements HostService {

    @Autowired
    private HostMapper hostMapper;

    @Autowired
    private RabbitMQService rabbitMQService;

    @Autowired
    private RedisCache redisCache;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public int saveHost(Host host) {
        return hostMapper.insert(host);
    }

    public ResponseResult findAll(MyParam param) {
        PageHelper.startPage(param.getPage(), param.getLimit());
        List<Host> hosts = hostMapper.findAll(param);

        for (Host host : hosts) {
            if (redisCache.getCacheObject("Heartbeat from " + host.getMacAddress()) == null && host.getIsAlive() == 1) {
                host.setIsAlive(0);
                hostMapper.updateByPrimaryKey(host);
            } else if (redisCache.getCacheObject("Heartbeat from " + host.getMacAddress()) != null && host.getIsAlive() == 0) {
                host.setIsAlive(1);
                hostMapper.updateByPrimaryKey(host);
            }
        }

        hosts = hostMapper.findAll(param);

        PageInfo<Host> pageInfo = new PageInfo<>(hosts);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }

    @Override
    public ResponseResult delete(Integer[] ids) {
        for (Integer id : ids) {
            hostMapper.deleteByPrimaryKey((long) id);
        }
        return new ResponseResult(0, "删除成功！");
    }

    @Override
    public List<Host> listAll() {
        List<Host> hosts = hostMapper.findAll(new MyParam()); // 调用 findAll 方法，不带分页参数
//        System.out.println("HostServiceImpl.listAll() - Hosts retrieved: " + (hosts != null ? hosts.size() : "null"));
        if (hosts != null) {
            for (Host host : hosts) {
                System.out.println("Host: " + host.getHostName() + " - " + host.getMacAddress());
            }
        }
        return hosts;
    }

    @Override
    public HashMap<String, Integer> getHostStatistics() {
        HashMap<String, Integer> statistics = new HashMap<>();
        // 已探测主机数量（总记录数）
        int detectedCount = hostMapper.countAll();
        // 在线主机数量（isAlive=1）
        int onlineCount = hostMapper.countAlive();
        statistics.put("detectedCount", detectedCount);
        statistics.put("onlineCount", onlineCount);
        return statistics;
    }

    @Override
    public Host selectByPrimaryKey(Integer id) {
        return hostMapper.selectByPrimaryKey(Long.valueOf(id));
    }

    @Override
    public Host selectByMacAddress(String macAddress) {
        return hostMapper.selectByMacAddress(macAddress);
    }

    @Override
    public HashMap<String, Object> hostDetect(HashMap<String, Object> data) {
        HashMap<String, Object> result = new HashMap<>();

        try {
            // 字段提取与校验
            if (!data.containsKey("id") || !data.containsKey("hostName") || !data.containsKey("macAddress") || !data.containsKey("type")) {
                throw new IllegalArgumentException("字段缺失");
            }


            Integer id = Integer.parseInt(data.get("id").toString());
            String hostName = data.get("hostName").toString();
            String originMacAddress = data.get("macAddress").toString();
            String macAddress = data.get("macAddress").toString().replace(":", "");
            String type = data.get("type").toString();

            // 构建消息体
            HashMap<String, Object> messageMap = new HashMap<>();
            messageMap.put("hostName", hostName);
            messageMap.put("macAddress", originMacAddress);
            messageMap.put("type", type);
            messageMap.put("id", id);
            messageMap.put("detectAccount", "on".equals(data.get("detect-account")));
            messageMap.put("detectService", "on".equals(data.get("detect-service")));
            messageMap.put("detectProcess", "on".equals(data.get("detect-process")));
            messageMap.put("detectApp", "on".equals(data.get("detect-app")));

            if (redisCache.getCacheObject("Heartbeat from " + originMacAddress) == null) {
                throw new IllegalAccessException("主机不在线！");
            }

            // 发送消息（默认 exchange，队列名以 MAC 地址标识）
            rabbitMQService.sendMessage("", "agentQueue" + macAddress, JSON.toJSONString(messageMap));

            // 成功响应
            result.put("code", 0);
            result.put("msg", "接收成功");
        } catch (IllegalArgumentException e) {
            // 错误响应
            result.put("code", 1001);
            result.put("msg", "字段格式有误");
        } catch (IllegalAccessException e) {
            result.put("code", 1002);
            result.put("msg", e.getMessage());
            return result;
        }

        return result;
    }

    @Override
    public Integer isHostAlive(Integer id){
        return jdbcTemplate.queryForObject("SELECT is_alive FROM host WHERE id = ?", Integer.class, id);
    }

    @Override
    public Integer isHostAlive(String macAddress){
        return jdbcTemplate.queryForObject("SELECT is_alive FROM host WHERE mac_address = ?",Integer.class,macAddress);
    }
}
