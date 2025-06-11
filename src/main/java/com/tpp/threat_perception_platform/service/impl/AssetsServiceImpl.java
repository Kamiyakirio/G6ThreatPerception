package com.tpp.threat_perception_platform.service.impl;

import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.tpp.threat_perception_platform.asset.Account;
import com.tpp.threat_perception_platform.asset.App;
import com.tpp.threat_perception_platform.asset.Process;
import com.tpp.threat_perception_platform.dao.*;
import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.pojo.Role;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.AssetsService;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.security.auth.login.AccountException;
import java.util.List;

@Service
public class AssetsServiceImpl implements AssetsService {

    @Autowired
    private AccountMapper accountMapper;
    @Autowired
    private AppMapper appMapper;
    @Autowired
    private ProcessMapper processMapper;
    @Autowired
    private ServiceMapper serviceMapper;

    @Override
    public ResponseResult findAll(MyParam param) {
        return null;
    }

    public ResponseResult accountList(MyParam param, String macAddress) {
        // 设置分页参数geInfo<>(roleList);

        PageHelper.startPage(param.getPage(), param.getLimit());
        // 查询所有
        List<Account> accountList = accountMapper.selectAllByMacAddress(macAddress);
        // 构架pageInfo
        PageInfo<Account> pageInfo = new PageInfo(accountList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }

    @Override
    public ResponseResult appList(MyParam param, String macAddress) {
        PageHelper.startPage(param.getPage(), param.getLimit());
        List<App> appList = appMapper.selectAllByMacAddress(macAddress);
        PageInfo<App> pageInfo = new PageInfo<>(appList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }

    @Override
    public ResponseResult processList(MyParam param, String macAddress) {
        PageHelper.startPage(param.getPage(), param.getLimit());
        List<Process> processList = processMapper.selectAllByMacAddress(macAddress);
        PageInfo<Process> pageInfo = new PageInfo<>(processList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }
    @Override
    public ResponseResult serviceList(MyParam param, String macAddress) {
        PageHelper.startPage(param.getPage(), param.getLimit());
        List<com.tpp.threat_perception_platform.asset.Service> serviceList = serviceMapper.selectAllByMacAddress(macAddress);
        PageInfo<com.tpp.threat_perception_platform.asset.Service> pageInfo = new PageInfo<>(serviceList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }

//    public ResponseResult appList(MyParam param) {
//        // 设置分页参数geInfo<>(roleList);
//
//        PageHelper.startPage(param.getPage(), param.getLimit());
//        // 查询所有
//        List<App> appList = Mapper.findAll(param);
//        // 构架pageInfo
//        PageInfo<App> pageInfo = new PageInfo(appList);
//        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
//    }
//
//
//    public ResponseResult processList(MyParam param) {
//        // 设置分页参数geInfo<>(roleList);
//
//        PageHelper.startPage(param.getPage(), param.getLimit());
//        // 查询所有
//        List<Process> processList = Mapper.findAll(param);
//        // 构架pageInfo
//        PageInfo<Process> pageInfo = new PageInfo(processtList);
//        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
//    }
//
//    public ResponseResult serviceList(MyParam param) {
//        // 设置分页参数geInfo<>(roleList);
//
//        PageHelper.startPage(param.getPage(), param.getLimit());
//        // 查询所有
//        List<Service> processList = Mapper.findAll(param);
//        // 构架pageInfo
//        PageInfo<Service> pageInfo = new PageInfo(serviceList);
//        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
//    }


}