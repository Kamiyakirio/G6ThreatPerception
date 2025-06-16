package com.tpp.threat_perception_platform.service.impl;

import com.alibaba.fastjson.JSON;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.tpp.threat_perception_platform.dao.HostMapper;
import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.param.SystemDetectParam;
import com.tpp.threat_perception_platform.pojo.Host;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.HostService;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import com.tpp.threat_perception_platform.utils.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
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
        System.out.println("HostServiceImpl.listAll() - Hosts retrieved: " + (hosts != null ? hosts.size() : "null"));
        if (hosts != null) {
            for (Host host : hosts) {
                System.out.println("Host: " + host.getHostName() + " - " + host.getMacAddress());
            }
        }
        return hosts;
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

            // 检查主机是否在线
            if (redisCache.getCacheObject("Heartbeat from " + originMacAddress) == null) {
                throw new IllegalAccessException("主机不在线！");
            }

            // 构建消息体
            HashMap<String, Object> messageMap = new HashMap<>();
            HashMap<String, Object> infoMap = new HashMap<>();
            infoMap.put("hostName", hostName);
            infoMap.put("macAddress", originMacAddress);
            infoMap.put("type", type);
            infoMap.put("id", id);
            messageMap.put("info", infoMap);

            // 发送消息到主机专属队列
            String queueName = "agentQueue" + macAddress;
            System.out.println("发送检测请求到队列: " + queueName);
            rabbitMQService.sendMessage("", queueName, JSON.toJSONString(messageMap));

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




}
