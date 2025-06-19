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
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.HashMap;

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
    private RabbitMQService rabbitMQService;

    @Autowired
    private RiskMapper riskMapper;

    @Override
    public ResponseResult findAll(MyParam param) {
        return null;
    }


    public ResponseResult accountList(MyParam param, String macAddress) {
        Integer ldid=accountMapper.selectLastDetectIdByMac(macAddress);
        List<Risk> riskList = riskMapper.selectAllByType("account");
        // 设置分页参数geInfo<>(roleList);
        PageHelper.startPage(param.getPage(), param.getLimit());
        // 查询所有
        List<Account> accountList = accountMapper.selectAllByDetectId(ldid);
        for (Account account : accountList) {
            for (Risk risk : riskList) {
                Pattern pattern = Pattern.compile(risk.getRe());
                Matcher matcher = pattern.matcher(account.getName());
                if (matcher.find()) {
                    account.setRisk(1);
                    account.setRiskDesc(risk.getRiskDesc());
                }
            }
        }
        // 构架pageInfo
        PageInfo<Account> pageInfo = new PageInfo(accountList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }


    @Override
    public ResponseResult appList(MyParam param, String macAddress) {
        Integer ldid=appMapper.selectLastDetectIdByMac(macAddress);
        List<Risk> riskList = riskMapper.selectAllByType("app");

        PageHelper.startPage(param.getPage(), param.getLimit());
        List<App> appList = appMapper.selectAllByDetectId(ldid);
        for (App app : appList) {
            for (Risk risk : riskList) {
                Pattern pattern = Pattern.compile(risk.getRe());
                Matcher matcher = pattern.matcher(app.getDisplayName());
                if (matcher.find()) {
                    app.setRisk(1);
                    app.setRiskDesc(risk.getRiskDesc());
                }
            }
        }

        PageInfo<App> pageInfo = new PageInfo<>(appList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }

    @Override
    public ResponseResult processList(MyParam param, String macAddress) {
        Integer ldid = processMapper.selectLastDetectIdByMac(macAddress);
        PageHelper.startPage(param.getPage(), param.getLimit());
        List<Process> processList = processMapper.selectAllByDetectId(ldid);

        List<Risk> riskList = riskMapper.selectAllByType("process");
        for (Process process : processList) {
            for (Risk risk : riskList) {
                Pattern pattern = Pattern.compile(risk.getRe());
                Matcher matcher = pattern.matcher(process.getName());
                if (matcher.find()) {
                    process.setRisk(1);
                    process.setRiskDesc(risk.getRiskDesc());
                }
            }
        }

        PageInfo<Process> pageInfo = new PageInfo<>(processList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }


    @Override
    public ResponseResult serviceList(MyParam param, String macAddress) {
        Integer ldid = serviceMapper.selectLastDetectIdByMac(macAddress);
        PageHelper.startPage(param.getPage(), param.getLimit());
        List<com.tpp.threat_perception_platform.asset.Service> serviceList = serviceMapper.selectByDetectId(ldid);

        List<Risk> riskList = riskMapper.selectAllByType("service");
        for (com.tpp.threat_perception_platform.asset.Service service : serviceList) {
            for (Risk risk : riskList) {
                Pattern pattern = Pattern.compile(risk.getRe());
                Matcher matcher = pattern.matcher(service.getName());
                if (matcher.find()) {
                    service.setRisk(1);
                    service.setRiskDesc(risk.getRiskDesc());
                }
            }
        }

        PageInfo<com.tpp.threat_perception_platform.asset.Service> pageInfo = new PageInfo<>(serviceList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }

    @Override
    public Map<String, Integer> getAssetsStatistics() {
        Map<String, Integer> statistics = new HashMap<>();
        
        // 获取账号数量
        int accountCount = accountMapper.selectTotalCount();
        statistics.put("accountCount", accountCount);
        
        // 获取服务数量
        int serviceCount = serviceMapper.selectTotalCount();
        statistics.put("serviceCount", serviceCount);
        
        // 获取进程数量
        int processCount = processMapper.selectTotalCount();
        statistics.put("processCount", processCount);
        
        // 获取软件数量
        int appCount = appMapper.selectTotalCount();
        statistics.put("appCount", appCount);
        
        return statistics;
    }

}