package com.tpp.threat_perception_platform.service.impl;

import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.tpp.threat_perception_platform.asset.Account;
import com.tpp.threat_perception_platform.asset.App;
import com.tpp.threat_perception_platform.asset.Process;
import com.tpp.threat_perception_platform.dao.*;
import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.pojo.Risk;
import com.tpp.threat_perception_platform.pojo.Role;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.AssetsService;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.security.auth.login.AccountException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    @Autowired
    private RiskMapper riskMapper;

    @Override
    public ResponseResult findAll(MyParam param) {
        return null;
    }

    public ResponseResult accountList(MyParam param, String macAddress) {
        // 设置分页参数geInfo<>(roleList);

        PageHelper.startPage(param.getPage(), param.getLimit());
        // 查询所有
        List<Account> accountList = accountMapper.selectAllByMacAddress(macAddress);

        List<Risk> riskList = riskMapper.selectAllByType("account");
        for (Account account : accountList) {
            for (Risk risk : riskList) {
                Pattern pattern = Pattern.compile(risk.getRe());
                Matcher matcher = pattern.matcher(account.getName());
                if (matcher.find()) {
                    account.setRisk(1);
                    account.setRiskDesc(risk.getDesc());
                }
            }
        }
        // 构架pageInfo
        PageInfo<Account> pageInfo = new PageInfo(accountList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }


    @Override
    public ResponseResult appList(MyParam param, String macAddress) {
        PageHelper.startPage(param.getPage(), param.getLimit());
        List<App> appList = appMapper.selectAllByMacAddress(macAddress);

        List<Risk> riskList = riskMapper.selectAllByType("app");
        for (App app : appList) {
            for (Risk risk : riskList) {
                Pattern pattern = Pattern.compile(risk.getRe());
                Matcher matcher = pattern.matcher(app.getDisplayName());
                if (matcher.find()) {
                    app.setRisk(1);
                    app.setRiskDesc(risk.getDesc());
                }
            }
        }

        PageInfo<App> pageInfo = new PageInfo<>(appList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }

    @Override
    public ResponseResult processList(MyParam param, String macAddress) {
        PageHelper.startPage(param.getPage(), param.getLimit());
        List<Process> processList = processMapper.selectAllByMacAddress(macAddress);

        List<Risk> riskList = riskMapper.selectAllByType("process");
        for (Process process : processList) {
            for (Risk risk : riskList) {
                Pattern pattern = Pattern.compile(risk.getRe());
                Matcher matcher = pattern.matcher(process.getName());
                if (matcher.find()) {
                    process.setRisk(1);
                    process.setRiskDesc(risk.getDesc());
                }
            }
        }

        PageInfo<Process> pageInfo = new PageInfo<>(processList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }


    @Override
    public ResponseResult serviceList(MyParam param, String macAddress) {
        PageHelper.startPage(param.getPage(), param.getLimit());
        List<com.tpp.threat_perception_platform.asset.Service> serviceList = serviceMapper.selectAllByMacAddress(macAddress);

        List<Risk> riskList = riskMapper.selectAllByType("service");
        for (com.tpp.threat_perception_platform.asset.Service service : serviceList) {
            for (Risk risk : riskList) {
                Pattern pattern = Pattern.compile(risk.getRe());
                Matcher matcher = pattern.matcher(service.getName());
                if (matcher.find()) {
                    service.setRisk(1);
                    service.setRiskDesc(risk.getDesc());
                }
            }
        }

        PageInfo<com.tpp.threat_perception_platform.asset.Service> pageInfo = new PageInfo<>(serviceList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }


}