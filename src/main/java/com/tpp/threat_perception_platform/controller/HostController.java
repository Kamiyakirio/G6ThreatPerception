package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.pojo.Host;
import com.tpp.threat_perception_platform.pojo.Role;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.HostService;
import com.tpp.threat_perception_platform.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;

/**
 * 控制器：用于处理资产主机相关请求
 */
@Controller // 改为 @Controller，这样返回字符串才会被 Thymeleaf 渲染
@RequestMapping("/host")
public class HostController {

    @Autowired
    private HostService hostService;

    /**
     * 获取主机列表
     *
     * @param param 分页参数
     * @return 响应结果
     */
    @PostMapping("/list")
    @ResponseBody // 保留 @ResponseBody 用于返回 JSON 数据
    public ResponseResult hostList(MyParam param){
        return hostService.findAll(param);
    }

    /**
     * 删除主机
     *
     * @param ids 主机ID数组
     * @return 响应结果
     */
    @PostMapping("/delete")
    @ResponseBody
    public ResponseResult hostDelete(@RequestParam("ids[]") Integer[] ids){
        return hostService.delete(ids);
    }

    /**
     * 主机探测
     *
     * @param data 请求数据
     * @return 返回 HashMap 格式的结果
     */
    @PostMapping("/detect")
    @ResponseBody
    public HashMap<String, Object> hostDetect(@RequestBody HashMap<String, Object> data){
        return hostService.hostDetect(data);
    }

    @GetMapping("/host/list")
    @ResponseBody
    public ResponseResult listHosts(MyParam param) {
        return hostService.findAll(param);
    }

}
