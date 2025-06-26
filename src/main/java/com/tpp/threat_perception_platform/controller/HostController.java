package com.tpp.threat_perception_platform.controller;

import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.permission.RequiresPermission;
import com.tpp.threat_perception_platform.pojo.Host;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.HostService;
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
     * 获取主机列表（分页）
     */
//    @RequiresPermission("host.list")
    @PostMapping("/list")
    @ResponseBody
    public ResponseResult hostList(MyParam param){
        return hostService.findAll(param);
    }

    /**
     * 获取全部主机列表（不分页） - 来自 apprisk 分支
     */
    @GetMapping("/listAll")
    @ResponseBody
    public ResponseResult listAllHosts(){
        List<Host> hosts = hostService.listAll();
        return new ResponseResult(0, hosts);
    }

    /**
     * 获取主机统计数据（已探测/在线数量）
     */
    @GetMapping("/statistics")
    @ResponseBody
    public ResponseResult hostStatistics(){
        HashMap<String, Integer> statistics = hostService.getHostStatistics();
        return new ResponseResult(0, statistics);
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
     */
    @PostMapping("/detect")
    @ResponseBody
    public HashMap<String, Object> hostDetect(@RequestBody HashMap<String, Object> data){
        return hostService.hostDetect(data);
    }

    /**
     * 获取主机列表（分页，另一种路径）
     */
    @GetMapping("/list")
    @ResponseBody
    public ResponseResult listHosts(MyParam param) {
        return hostService.findAll(param);
    }

    @GetMapping("/isAlive")
    @ResponseBody
    public ResponseResult isAlive(@RequestParam Integer id) {return new ResponseResult(1,hostService.isHostAlive(id).toString());}
}
