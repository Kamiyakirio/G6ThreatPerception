package com.tpp.threat_perception_platform.service.impl;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.tpp.threat_perception_platform.dao.HostMapper;
import com.tpp.threat_perception_platform.dao.SystemAccessMapper;
import com.tpp.threat_perception_platform.dao.EventAuditMapper;
import com.tpp.threat_perception_platform.dao.PrivilegeRightsMapper;
import com.tpp.threat_perception_platform.dao.SystemSecurityOptionMapper;
import com.tpp.threat_perception_platform.dao.BaselineScanMapper;
import com.tpp.threat_perception_platform.pojo.BaselineItemResult;
import com.tpp.threat_perception_platform.pojo.SystemAccess;
import com.tpp.threat_perception_platform.pojo.EventAudit;
import com.tpp.threat_perception_platform.pojo.PrivilegeRights;
import com.tpp.threat_perception_platform.pojo.SystemSecurityOption;
import com.tpp.threat_perception_platform.pojo.BaselineScan;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.BaselineService;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import com.tpp.threat_perception_platform.utils.RedisCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Arrays;
import java.util.Collections;
import java.lang.reflect.Method;

@Slf4j
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

    @Autowired
    private SystemAccessMapper systemAccessMapper;

    @Autowired
    private EventAuditMapper eventAuditMapper;

    @Autowired
    private PrivilegeRightsMapper privilegeRightsMapper;

    @Autowired
    private SystemSecurityOptionMapper systemSecurityOptionMapper;

    @Autowired
    private BaselineScanMapper baselineScanMapper;

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
            
            // 1. 获取基线检测总数（从baseline_scan表）
            Integer totalCount = baselineScanMapper.selectTotalCount(null, null);
            statistics.put("totalCount", totalCount != null ? totalCount : 0);

            // 2. 获取系统配置检测数（从system_access表）
            String systemAccessSql = "SELECT COUNT(DISTINCT mac_address) FROM system_access";
            Integer systemCount = jdbcTemplate.queryForObject(systemAccessSql, Integer.class);
            statistics.put("systemCount", systemCount != null ? systemCount : 0);

            // 3. 获取安全策略检测数（从event_audit表）
            String securitySql = "SELECT COUNT(DISTINCT mac_address) FROM event_audit";
            Integer securityCount = jdbcTemplate.queryForObject(securitySql, Integer.class);
            statistics.put("securityCount", securityCount != null ? securityCount : 0);

            // 4. 获取风险项目数
            // 从各个表中统计状态不合格的项目数
            String riskSql = "SELECT " +
                    "(SELECT COUNT(*) FROM system_access WHERE type = 'result' AND (" +
                    "minimum_password_age < (SELECT minimum_password_age FROM system_access WHERE type = 'rule' LIMIT 1) OR " +
                    "maximum_password_age > (SELECT maximum_password_age FROM system_access WHERE type = 'rule' LIMIT 1) OR " +
                    "minimum_password_length < (SELECT minimum_password_length FROM system_access WHERE type = 'rule' LIMIT 1))) + " +
                    "(SELECT COUNT(*) FROM event_audit WHERE type = 'result' AND (" +
                    "audit_system_events != (SELECT audit_system_events FROM event_audit WHERE type = 'rule' LIMIT 1) OR " +
                    "audit_logon_events != (SELECT audit_logon_events FROM event_audit WHERE type = 'rule' LIMIT 1))) + " +
                    "(SELECT COUNT(*) FROM privilege_rights WHERE type = 'result' AND (" +
                    "se_shutdown_privilege != (SELECT se_shutdown_privilege FROM privilege_rights WHERE type = 'rule' LIMIT 1))) + " +
                    "(SELECT COUNT(*) FROM system_security_option WHERE type = 'result' AND (" +
                    "no_lm_hash != (SELECT no_lm_hash FROM system_security_option WHERE type = 'rule' LIMIT 1) OR " +
                    "limit_blank_password_use != (SELECT limit_blank_password_use FROM system_security_option WHERE type = 'rule' LIMIT 1)))";
            
            Integer riskCount = jdbcTemplate.queryForObject(riskSql, Integer.class);
            statistics.put("riskCount", riskCount != null ? riskCount : 0);

            return new ResponseResult<>(0, "获取统计数据成功", statistics);
        } catch (Exception e) {
            log.error("获取统计数据失败: {}", e.getMessage(), e);
            return new ResponseResult<>(500, "获取统计数据失败: " + e.getMessage(), null);
        }
    }

    @Override
    public List<BaselineItemResult> getBaselineDetail(String macAddress) {
        List<BaselineItemResult> results = new ArrayList<>();
        
        try {
            log.info("Getting baseline details for MAC address: {}", macAddress);
        
        // 1. 系统访问配置比较
            List<SystemAccess> ruleAccess = systemAccessMapper.selectByType("rule");
            List<SystemAccess> resultAccess = systemAccessMapper.selectByTypeAndMac("result", macAddress);
            log.debug("System Access - Rules: {}, Results: {}", ruleAccess.size(), resultAccess.size());
            
            if (!ruleAccess.isEmpty()) {
                SystemAccess rule = ruleAccess.get(0);
                if (!resultAccess.isEmpty()) {
                    log.debug("Processing system access results");
                    SystemAccess result = resultAccess.get(0);
            
            // 密码最短留存期
            addBaselineItem(results, "密码最短留存期", 
                        String.valueOf(rule.getMinimumPasswordAge()),
                        String.valueOf(result.getMinimumPasswordAge()),
                        result.getMinimumPasswordAge() <= rule.getMinimumPasswordAge(),
                        "值小于规则值即合格", "system_access");
            
            // 密码最长留存期
            addBaselineItem(results, "密码最长留存期",
                        String.valueOf(rule.getMaximumPasswordAge()),
                        String.valueOf(result.getMaximumPasswordAge()),
                        result.getMaximumPasswordAge() <= rule.getMaximumPasswordAge(),
                        "值小于规则值即合格", "system_access");
            
            // 密码最小长度
            addBaselineItem(results, "密码最小长度",
                        String.valueOf(rule.getMinimumPasswordLength()),
                        String.valueOf(result.getMinimumPasswordLength()),
                        result.getMinimumPasswordLength() >= rule.getMinimumPasswordLength(),
                        "值大于规则值即合格", "system_access");
            
            // 密码复杂度要求
            addBaselineItem(results, "密码复杂度要求",
                        String.valueOf(rule.getPasswordComplexity()),
                        String.valueOf(result.getPasswordComplexity()),
                        result.getPasswordComplexity().equals(rule.getPasswordComplexity()),
                        "值必须与规则值相同", "system_access");

                    // 密码历史长度
                    addBaselineItem(results, "密码历史长度",
                        String.valueOf(rule.getPasswordHistorySize()),
                        String.valueOf(result.getPasswordHistorySize()),
                        result.getPasswordHistorySize() >= rule.getPasswordHistorySize(),
                        "值大于规则值即合格", "system_access");

                    // 账户锁定阈值
                    addBaselineItem(results, "账户锁定阈值",
                        String.valueOf(rule.getLockoutBadCount()),
                        String.valueOf(result.getLockoutBadCount()),
                        result.getLockoutBadCount() <= rule.getLockoutBadCount() && result.getLockoutBadCount() > 0,
                        "值必须大于0且小于规则值", "system_access");

                    // 必须登录才能更改密码
                    addBaselineItem(results, "必须登录才能更改密码",
                        String.valueOf(rule.getRequireLogonToChangePassword()),
                        String.valueOf(result.getRequireLogonToChangePassword()),
                        result.getRequireLogonToChangePassword().equals(rule.getRequireLogonToChangePassword()),
                        "值必须与规则值相同", "system_access");

                    // 强制用户在时间到期时注销
                    addBaselineItem(results, "强制用户在时间到期时注销",
                        String.valueOf(rule.getForceLogoffWhenHourExpire()),
                        String.valueOf(result.getForceLogoffWhenHourExpire()),
                        result.getForceLogoffWhenHourExpire().equals(rule.getForceLogoffWhenHourExpire()),
                        "值必须与规则值相同", "system_access");

                    // 管理员账户状态
                    addBaselineItem(results, "管理员账户状态",
                        String.valueOf(rule.getEnableAdminAccount()),
                        String.valueOf(result.getEnableAdminAccount()),
                        result.getEnableAdminAccount().equals(rule.getEnableAdminAccount()),
                        "值必须与规则值相同", "system_access");

                    // 访客账户状态
                    addBaselineItem(results, "访客账户状态",
                        String.valueOf(rule.getEnableGuestAccount()),
                        String.valueOf(result.getEnableGuestAccount()),
                        result.getEnableGuestAccount().equals(rule.getEnableGuestAccount()),
                        "值必须与规则值相同", "system_access");

                    // 明文密码
                    addBaselineItem(results, "明文密码",
                        String.valueOf(rule.getClearTextPassword()),
                        String.valueOf(result.getClearTextPassword()),
                        result.getClearTextPassword().equals(rule.getClearTextPassword()),
                        "值必须与规则值相同", "system_access");

                    // LSA匿名名称查找
                    addBaselineItem(results, "LSA匿名名称查找",
                        String.valueOf(rule.getLsaAnonymousNameLookup()),
                        String.valueOf(result.getLsaAnonymousNameLookup()),
                        result.getLsaAnonymousNameLookup().equals(rule.getLsaAnonymousNameLookup()),
                        "值必须与规则值相同", "system_access");
                } else {
                    log.debug("No system access results found, adding placeholder");
                    addBaselineItem(results, "系统访问配置", 
                        "已配置规则值",
                        "未检测",
                        false,
                        "需要进行系统访问配置检测", "system_access");
                }
        }

        // 2. 事件审计配置比较
            List<EventAudit> ruleAudit = eventAuditMapper.selectByType("rule");
            List<EventAudit> resultAudit = eventAuditMapper.selectByTypeAndMac("result", macAddress);
            log.debug("Event Audit - Rules: {}, Results: {}", ruleAudit.size(), resultAudit.size());
            
            if (!ruleAudit.isEmpty()) {
                EventAudit rule = ruleAudit.get(0);
                if (!resultAudit.isEmpty()) {
                    log.debug("Processing event audit results");
                    EventAudit result = resultAudit.get(0);
            
            // 审核系统事件
            addBaselineItem(results, "审核系统事件",
                        String.valueOf(rule.getAuditSystemEvents()),
                        String.valueOf(result.getAuditSystemEvents()),
                        compareEventAudit(rule, result),
                        "值必须与规则值相同", "event_audit");
            
            // 审核登录事件
            addBaselineItem(results, "审核登录事件",
                        String.valueOf(rule.getAuditLogonEvents()),
                        String.valueOf(result.getAuditLogonEvents()),
                        compareEventAudit(rule, result),
                        "值必须与规则值相同", "event_audit");
            
            // 审核对象访问
            addBaselineItem(results, "审核对象访问",
                        String.valueOf(rule.getAuditObjectAccess()),
                        String.valueOf(result.getAuditObjectAccess()),
                        compareEventAudit(rule, result),
                        "值必须与规则值相同", "event_audit");

                    // 审核特权使用
                    addBaselineItem(results, "审核特权使用",
                        String.valueOf(rule.getAuditPrivilegeUse()),
                        String.valueOf(result.getAuditPrivilegeUse()),
                        compareEventAudit(rule, result),
                        "值必须与规则值相同", "event_audit");

                    // 审核策略更改
                    addBaselineItem(results, "审核策略更改",
                        String.valueOf(rule.getAuditPolicyChange()),
                        String.valueOf(result.getAuditPolicyChange()),
                        compareEventAudit(rule, result),
                        "值必须与规则值相同", "event_audit");

                    // 审核账户管理
                    addBaselineItem(results, "审核账户管理",
                        String.valueOf(rule.getAuditAccountManage()),
                        String.valueOf(result.getAuditAccountManage()),
                        compareEventAudit(rule, result),
                        "值必须与规则值相同", "event_audit");

                    // 审核进程追踪
                    addBaselineItem(results, "审核进程追踪",
                        String.valueOf(rule.getAuditProcessTracking()),
                        String.valueOf(result.getAuditProcessTracking()),
                        compareEventAudit(rule, result),
                        "值必须与规则值相同", "event_audit");

                    // 审核目录服务访问
                    addBaselineItem(results, "审核目录服务访问",
                        String.valueOf(rule.getAuditDsAccess()),
                        String.valueOf(result.getAuditDsAccess()),
                        compareEventAudit(rule, result),
                        "值必须与规则值相同", "event_audit");

                    // 审核账户登录
                    addBaselineItem(results, "审核账户登录",
                        String.valueOf(rule.getAuditAccountLogon()),
                        String.valueOf(result.getAuditAccountLogon()),
                        compareEventAudit(rule, result),
                        "值必须与规则值相同", "event_audit");
                } else {
                    log.debug("No event audit results found, adding placeholder");
                    addBaselineItem(results, "事件审计配置", 
                        "已配置规则值",
                        "未检测",
                        false,
                        "需要进行事件审计配置检测", "event_audit");
                }
        }

        // 3. 权限配置比较
            List<PrivilegeRights> ruleRights = privilegeRightsMapper.selectByType("rule");
            List<PrivilegeRights> resultRights = privilegeRightsMapper.selectByTypeAndMac("result", macAddress);
            log.debug("Privilege Rights - Rules: {}, Results: {}", ruleRights.size(), resultRights.size());
            
            if (!ruleRights.isEmpty()) {
                PrivilegeRights rule = ruleRights.get(0);
                if (!resultRights.isEmpty()) {
                    log.debug("Processing privilege rights results");
                    PrivilegeRights result = resultRights.get(0);
            
            // 单一进程权限
            addBaselineItem(results, "单一进程权限",
                        rule.getSeProfileSingleProcessPrivilege(),
                        result.getSeProfileSingleProcessPrivilege(),
                        comparePrivilegeRights(rule, result),
                        "权限列表必须匹配规则值", "privilege_rights");

            // 远程关机权限
            addBaselineItem(results, "远程关机权限",
                        rule.getSeRemoteShutdownPrivilege(),
                        result.getSeRemoteShutdownPrivilege(),
                        comparePrivilegeRights(rule, result),
                        "权限列表必须匹配规则值", "privilege_rights");

                    // 本地关机权限
                    addBaselineItem(results, "本地关机权限",
                        rule.getSeShutdownPrivilege(),
                        result.getSeShutdownPrivilege(),
                        comparePrivilegeRights(rule, result),
                        "权限列表必须匹配规则值", "privilege_rights");
                } else {
                    log.debug("No privilege rights results found, adding placeholder");
                    addBaselineItem(results, "权限配置", 
                        "已配置规则值",
                        "未检测",
                        false,
                        "需要进行权限配置检测", "privilege_rights");
                }
        }

        // 4. 系统安全选项比较
            List<SystemSecurityOption> ruleOption = systemSecurityOptionMapper.selectByType("rule");
            List<SystemSecurityOption> resultOption = systemSecurityOptionMapper.selectByTypeAndMac("result", macAddress);
            log.debug("System Security Options - Rules: {}, Results: {}", ruleOption.size(), resultOption.size());
            
            if (!ruleOption.isEmpty()) {
                SystemSecurityOption rule = ruleOption.get(0);
                if (!resultOption.isEmpty()) {
                    log.debug("Processing system security options results");
                    SystemSecurityOption result = resultOption.get(0);
            
            // LM哈希
            addBaselineItem(results, "禁用LM哈希",
                        String.valueOf(rule.getNoLmHash()),
                        String.valueOf(result.getNoLmHash()),
                        compareSystemSecurityOption(rule, result),
                        "值必须与规则值相同", "system_security_option");
            
            // 限制空密码使用
            addBaselineItem(results, "限制空密码使用",
                        String.valueOf(rule.getLimitBlankPasswordUse()),
                        String.valueOf(result.getLimitBlankPasswordUse()),
                        compareSystemSecurityOption(rule, result),
                        "值必须与规则值相同", "system_security_option");
            
            // 限制匿名访问
            addBaselineItem(results, "限制匿名访问",
                        String.valueOf(rule.getRestrictAnonymous()),
                        String.valueOf(result.getRestrictAnonymous()),
                        compareSystemSecurityOption(rule, result),
                        "值必须与规则值相同", "system_security_option");

                    // 不显示上次登录用户名
                    addBaselineItem(results, "不显示上次登录用户名",
                        String.valueOf(rule.getDontDisplayLastUserName()),
                        String.valueOf(result.getDontDisplayLastUserName()),
                        compareSystemSecurityOption(rule, result),
                        "值必须与规则值相同", "system_security_option");

                    // 启用明文密码
                    addBaselineItem(results, "启用明文密码",
                        String.valueOf(rule.getEnablePlainTextPassword()),
                        String.valueOf(result.getEnablePlainTextPassword()),
                        compareSystemSecurityOption(rule, result),
                        "值必须与规则值相同", "system_security_option");

                    // 关机时清除页面文件
                    addBaselineItem(results, "关机时清除页面文件",
                        String.valueOf(rule.getClearPageFileAtShutdown()),
                        String.valueOf(result.getClearPageFileAtShutdown()),
                        compareSystemSecurityOption(rule, result),
                        "值必须与规则值相同", "system_security_option");
                } else {
                    log.debug("No system security options found, adding placeholder");
                    addBaselineItem(results, "系统安全选项", 
                        "已配置规则值",
                        "未检测",
                        false,
                        "需要进行系统安全选项检测", "system_security_option");
                }
            }

            log.info("Baseline detail processing completed. Found {} items", results.size());
        return results;
        } catch (Exception e) {
            log.error("获取基线检测详情失败: {}", e.getMessage(), e);
            throw e;  // 让异常继续向上传播，以便更好地诊断问题
        }
    }

    private void addBaselineItem(List<BaselineItemResult> results, String name, String standardValue, 
                               String actualValue, boolean isValid, String description, String type) {
        try {
        BaselineItemResult item = new BaselineItemResult();
        item.setName(name);
            item.setStandardValue(standardValue != null ? standardValue : "-");
            item.setActualValue(actualValue != null ? actualValue : "-");
        item.setStatus(isValid ? 1 : 0);
        item.setDescription(description);
        item.setType(type);
        results.add(item);
        } catch (Exception e) {
            log.error("添加基线检测项失败: " + name, e);
        }
    }

    private boolean compareSystemAccess(SystemAccess standardRule, SystemAccess actualValue) {
        if (standardRule == null || actualValue == null) {
            return false;
        }

        // 创建一个计数器来跟踪匹配的字段数和总字段数
        int matchedFields = 0;
        int totalFields = 0;

        // 最小密码年龄
        if (standardRule.getMinimumPasswordAge() != null && actualValue.getMinimumPasswordAge() != null) {
            totalFields++;
            if (standardRule.getMinimumPasswordAge().equals(actualValue.getMinimumPasswordAge())) {
                matchedFields++;
            }
        }

        // 最大密码年龄
        if (standardRule.getMaximumPasswordAge() != null && actualValue.getMaximumPasswordAge() != null) {
            totalFields++;
            if (standardRule.getMaximumPasswordAge().equals(actualValue.getMaximumPasswordAge())) {
                matchedFields++;
            }
        }

        // 最小密码长度
        if (standardRule.getMinimumPasswordLength() != null && actualValue.getMinimumPasswordLength() != null) {
            totalFields++;
            if (standardRule.getMinimumPasswordLength().equals(actualValue.getMinimumPasswordLength())) {
                matchedFields++;
            }
        }

        // 密码复杂度
        if (standardRule.getPasswordComplexity() != null && actualValue.getPasswordComplexity() != null) {
            totalFields++;
            if (standardRule.getPasswordComplexity().equals(actualValue.getPasswordComplexity())) {
                matchedFields++;
            }
        }

        // 密码历史大小
        if (standardRule.getPasswordHistorySize() != null && actualValue.getPasswordHistorySize() != null) {
            totalFields++;
            if (standardRule.getPasswordHistorySize().equals(actualValue.getPasswordHistorySize())) {
                matchedFields++;
            }
        }

        // 账户锁定阈值
        if (standardRule.getLockoutBadCount() != null && actualValue.getLockoutBadCount() != null) {
            totalFields++;
            if (standardRule.getLockoutBadCount().equals(actualValue.getLockoutBadCount())) {
                matchedFields++;
            }
        }

        // 必须登录才能更改密码
        if (standardRule.getRequireLogonToChangePassword() != null && actualValue.getRequireLogonToChangePassword() != null) {
            totalFields++;
            if (standardRule.getRequireLogonToChangePassword().equals(actualValue.getRequireLogonToChangePassword())) {
                matchedFields++;
            }
        }

        // 强制用户在时间到期时注销
        if (standardRule.getForceLogoffWhenHourExpire() != null && actualValue.getForceLogoffWhenHourExpire() != null) {
            totalFields++;
            if (standardRule.getForceLogoffWhenHourExpire().equals(actualValue.getForceLogoffWhenHourExpire())) {
                matchedFields++;
            }
        }

        // 管理员账户状态
        if (standardRule.getEnableAdminAccount() != null && actualValue.getEnableAdminAccount() != null) {
            totalFields++;
            if (standardRule.getEnableAdminAccount().equals(actualValue.getEnableAdminAccount())) {
                matchedFields++;
            }
        }

        // 访客账户状态
        if (standardRule.getEnableGuestAccount() != null && actualValue.getEnableGuestAccount() != null) {
            totalFields++;
            if (standardRule.getEnableGuestAccount().equals(actualValue.getEnableGuestAccount())) {
                matchedFields++;
            }
        }

        // 明文密码
        if (standardRule.getClearTextPassword() != null && actualValue.getClearTextPassword() != null) {
            totalFields++;
            if (standardRule.getClearTextPassword().equals(actualValue.getClearTextPassword())) {
                matchedFields++;
            }
        }

        // LSA匿名名称查找
        if (standardRule.getLsaAnonymousNameLookup() != null && actualValue.getLsaAnonymousNameLookup() != null) {
            totalFields++;
            if (standardRule.getLsaAnonymousNameLookup().equals(actualValue.getLsaAnonymousNameLookup())) {
                matchedFields++;
            }
        }

        // 如果没有任何可比较的字段，返回false
        if (totalFields == 0) {
            return false;
        }

        // 如果匹配率超过80%，则认为是合格的
        return (double) matchedFields / totalFields >= 0.8;
    }

    private boolean compareEventAudit(EventAudit standardRule, EventAudit actualValue) {
        if (standardRule == null || actualValue == null) {
            return false;
        }

        // 创建一个计数器来跟踪匹配的字段数和总字段数
        int matchedFields = 0;
        int totalFields = 0;

        // 审计系统事件
        if (standardRule.getAuditSystemEvents() != null && actualValue.getAuditSystemEvents() != null) {
            totalFields++;
            if (standardRule.getAuditSystemEvents().equals(actualValue.getAuditSystemEvents())) {
                matchedFields++;
            }
        }

        // 审计登录事件
        if (standardRule.getAuditLogonEvents() != null && actualValue.getAuditLogonEvents() != null) {
            totalFields++;
            if (standardRule.getAuditLogonEvents().equals(actualValue.getAuditLogonEvents())) {
                matchedFields++;
            }
        }

        // 审计对象访问
        if (standardRule.getAuditObjectAccess() != null && actualValue.getAuditObjectAccess() != null) {
            totalFields++;
            if (standardRule.getAuditObjectAccess().equals(actualValue.getAuditObjectAccess())) {
                matchedFields++;
            }
        }

        // 审计策略更改
        if (standardRule.getAuditPolicyChange() != null && actualValue.getAuditPolicyChange() != null) {
            totalFields++;
            if (standardRule.getAuditPolicyChange().equals(actualValue.getAuditPolicyChange())) {
                matchedFields++;
            }
        }

        // 审计权限使用
        if (standardRule.getAuditPrivilegeUse() != null && actualValue.getAuditPrivilegeUse() != null) {
            totalFields++;
            if (standardRule.getAuditPrivilegeUse().equals(actualValue.getAuditPrivilegeUse())) {
                matchedFields++;
            }
        }

        // 审计进程跟踪
        if (standardRule.getAuditProcessTracking() != null && actualValue.getAuditProcessTracking() != null) {
            totalFields++;
            if (standardRule.getAuditProcessTracking().equals(actualValue.getAuditProcessTracking())) {
                matchedFields++;
            }
        }

        // 审计目录服务访问
        if (standardRule.getAuditDsAccess() != null && actualValue.getAuditDsAccess() != null) {
            totalFields++;
            if (standardRule.getAuditDsAccess().equals(actualValue.getAuditDsAccess())) {
                matchedFields++;
            }
        }

        // 审计账户管理
        if (standardRule.getAuditAccountManage() != null && actualValue.getAuditAccountManage() != null) {
            totalFields++;
            if (standardRule.getAuditAccountManage().equals(actualValue.getAuditAccountManage())) {
                matchedFields++;
            }
        }

        // 审计账户登录
        if (standardRule.getAuditAccountLogon() != null && actualValue.getAuditAccountLogon() != null) {
            totalFields++;
            if (standardRule.getAuditAccountLogon().equals(actualValue.getAuditAccountLogon())) {
                matchedFields++;
            }
        }

        // 如果没有任何可比较的字段，返回false
        if (totalFields == 0) {
            return false;
        }

        // 如果匹配率超过80%，则认为是合格的
        return (double) matchedFields / totalFields >= 0.8;
    }

    private boolean comparePrivilegeRights(PrivilegeRights standardRule, PrivilegeRights actualValue) {
        if (standardRule == null || actualValue == null) {
            return false;
        }

        // 创建一个计数器来跟踪匹配的字段数和总字段数
        int matchedFields = 0;
        int totalFields = 0;

        // 单进程配置权限
        if (standardRule.getSeProfileSingleProcessPrivilege() != null && actualValue.getSeProfileSingleProcessPrivilege() != null) {
            totalFields++;
            if (comparePrivilegeList(standardRule.getSeProfileSingleProcessPrivilege(), actualValue.getSeProfileSingleProcessPrivilege())) {
                matchedFields++;
            }
        }

        // 远程关机权限
        if (standardRule.getSeRemoteShutdownPrivilege() != null && actualValue.getSeRemoteShutdownPrivilege() != null) {
            totalFields++;
            if (comparePrivilegeList(standardRule.getSeRemoteShutdownPrivilege(), actualValue.getSeRemoteShutdownPrivilege())) {
                matchedFields++;
            }
        }

        // 本地关机权限
        if (standardRule.getSeShutdownPrivilege() != null && actualValue.getSeShutdownPrivilege() != null) {
            totalFields++;
            if (comparePrivilegeList(standardRule.getSeShutdownPrivilege(), actualValue.getSeShutdownPrivilege())) {
                matchedFields++;
            }
        }

        // 如果没有任何可比较的字段，返回false
        if (totalFields == 0) {
            return false;
        }

        // 如果匹配率超过80%，则认为是合格的
        return (double) matchedFields / totalFields >= 0.8;
    }

    // 辅助方法：比较权限列表
    private boolean comparePrivilegeList(String ruleList, String actualList) {
        if (ruleList == null || actualList == null) {
            return false;
        }

        // 将字符串转换为列表
        List<String> ruleItems = Arrays.asList(ruleList.replace("[", "").replace("]", "").split(",\\s*"));
        List<String> actualItems = Arrays.asList(actualList.replace("[", "").replace("]", "").split(",\\s*"));

        // 检查规则列表中的所有项是否都在实际列表中
        for (String ruleItem : ruleItems) {
            if (!actualItems.contains(ruleItem.trim())) {
                return false;
            }
        }

        // 检查实际列表中是否有不应该存在的项
        for (String actualItem : actualItems) {
            if (!ruleItems.contains(actualItem.trim())) {
                return false;
            }
        }

        return true;
    }

    private boolean compareSystemSecurityOption(SystemSecurityOption standardRule, SystemSecurityOption actualValue) {
        if (standardRule == null || actualValue == null) {
            return false;
        }

        // 创建一个计数器来跟踪匹配的字段数和总字段数
        int matchedFields = 0;
        int totalFields = 0;

        // 不存储LM哈希值
        if (standardRule.getNoLmHash() != null && actualValue.getNoLmHash() != null) {
            totalFields++;
            if (standardRule.getNoLmHash().equals(actualValue.getNoLmHash())) {
                matchedFields++;
            }
        }

        // 限制使用空密码
        if (standardRule.getLimitBlankPasswordUse() != null && actualValue.getLimitBlankPasswordUse() != null) {
            totalFields++;
            if (standardRule.getLimitBlankPasswordUse().equals(actualValue.getLimitBlankPasswordUse())) {
                matchedFields++;
            }
        }

        // 限制匿名访问
        if (standardRule.getRestrictAnonymous() != null && actualValue.getRestrictAnonymous() != null) {
            totalFields++;
            if (standardRule.getRestrictAnonymous().equals(actualValue.getRestrictAnonymous())) {
                matchedFields++;
            }
        }

        // 不显示上次登录用户名
        if (standardRule.getDontDisplayLastUserName() != null && actualValue.getDontDisplayLastUserName() != null) {
            totalFields++;
            if (standardRule.getDontDisplayLastUserName().equals(actualValue.getDontDisplayLastUserName())) {
                matchedFields++;
            }
        }

        // 启用明文密码
        if (standardRule.getEnablePlainTextPassword() != null && actualValue.getEnablePlainTextPassword() != null) {
            totalFields++;
            if (standardRule.getEnablePlainTextPassword().equals(actualValue.getEnablePlainTextPassword())) {
                matchedFields++;
            }
        }

        // 关机时清除页面文件
        if (standardRule.getClearPageFileAtShutdown() != null && actualValue.getClearPageFileAtShutdown() != null) {
            totalFields++;
            if (standardRule.getClearPageFileAtShutdown().equals(actualValue.getClearPageFileAtShutdown())) {
                matchedFields++;
            }
        }

        // 如果没有任何可比较的字段，返回false
        if (totalFields == 0) {
            return false;
        }

        // 如果匹配率超过80%，则认为是合格的
        return (double) matchedFields / totalFields >= 0.8;
    }

    public void processBaselineData(Map<String, Object> data) {
        String macAddress = (String) data.get("macAddress");
        JSONObject baselineData = (JSONObject) data.get("baselineData");

        try {
            // 1. 处理并保存 System Access 数据
            if (baselineData.containsKey("system access")) {
                processSystemAccess(macAddress, baselineData.getJSONObject("system access"));
            }

            // 2. 处理并保存 Event Audit 数据
            if (baselineData.containsKey("event audit")) {
                processEventAudit(macAddress, baselineData.getJSONObject("event audit"));
            }

            // 3. 处理并保存 Privilege Rights 数据
            if (baselineData.containsKey("privilege rights")) {
                processPrivilegeRights(macAddress, baselineData.getJSONObject("privilege rights"));
            }

            // 4. 处理并保存 System Security Option 数据
            if (baselineData.containsKey("system security option")) {
                processSystemSecurityOption(macAddress, baselineData.getJSONObject("system security option"));
            }

            // 5. 进行基线检查
            checkBaseline(Collections.singletonMap("macAddress", macAddress));
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("处理基线数据失败: " + e.getMessage());
        }
    }

    private void processSystemAccess(String macAddress, JSONObject sysAccessJson) {
        try {
            SystemAccess systemAccess = new SystemAccess();
            systemAccess.setMacAddress(macAddress);
            systemAccess.setType("result");

            // 添加数据验证
            validateAndSetSystemAccessFields(systemAccess, sysAccessJson);

            // 保存到数据库
            systemAccessMapper.insertSelective(systemAccess);
        } catch (Exception e) {
            System.err.println("处理系统访问数据失败: " + e.getMessage());
            throw e;
        }
    }

    private void validateAndSetSystemAccessFields(SystemAccess systemAccess, JSONObject json) {
        // 定义所有需要验证的字段及其验证规则
        try {
            // 密码最短使用期限
            if (json.containsKey("MinimumPasswordAge")) {
                int minPwdAge = Integer.parseInt(json.getString("MinimumPasswordAge"));
                if (minPwdAge < 0) throw new IllegalArgumentException("MinimumPasswordAge must be non-negative");
                systemAccess.setMinimumPasswordAge(minPwdAge);
            }

            // 密码最长使用期限
            if (json.containsKey("MaximumPasswordAge")) {
                int maxPwdAge = Integer.parseInt(json.getString("MaximumPasswordAge"));
                if (maxPwdAge < 0) throw new IllegalArgumentException("MaximumPasswordAge must be non-negative");
                systemAccess.setMaximumPasswordAge(maxPwdAge);
            }

            // 密码最小长度
            if (json.containsKey("MinimumPasswordLength")) {
                int minPwdLength = Integer.parseInt(json.getString("MinimumPasswordLength"));
                if (minPwdLength < 0) throw new IllegalArgumentException("MinimumPasswordLength must be non-negative");
                systemAccess.setMinimumPasswordLength(minPwdLength);
            }

            // 密码复杂度要求
            if (json.containsKey("PasswordComplexity")) {
                int pwdComplexity = Integer.parseInt(json.getString("PasswordComplexity"));
                if (pwdComplexity < 0 || pwdComplexity > 1) throw new IllegalArgumentException("PasswordComplexity must be 0 or 1");
                systemAccess.setPasswordComplexity(pwdComplexity);
            }

            // 密码历史长度
            if (json.containsKey("PasswordHistorySize")) {
                int pwdHistorySize = Integer.parseInt(json.getString("PasswordHistorySize"));
                if (pwdHistorySize < 0) throw new IllegalArgumentException("PasswordHistorySize must be non-negative");
                systemAccess.setPasswordHistorySize(pwdHistorySize);
            }

            // 账户锁定阈值
            if (json.containsKey("LockoutBadCount")) {
                int lockoutBadCount = Integer.parseInt(json.getString("LockoutBadCount"));
                if (lockoutBadCount < 0) throw new IllegalArgumentException("LockoutBadCount must be non-negative");
                systemAccess.setLockoutBadCount(lockoutBadCount);
            }

            // 必须登录才能更改密码
            if (json.containsKey("RequireLogonToChangePassword")) {
                int requireLogon = Integer.parseInt(json.getString("RequireLogonToChangePassword"));
                if (requireLogon < 0 || requireLogon > 1) throw new IllegalArgumentException("RequireLogonToChangePassword must be 0 or 1");
                systemAccess.setRequireLogonToChangePassword(requireLogon);
            }

            // 到期强制注销
            if (json.containsKey("ForceLogoffWhenHourExpire")) {
                int forceLogoff = Integer.parseInt(json.getString("ForceLogoffWhenHourExpire"));
                if (forceLogoff < 0 || forceLogoff > 1) throw new IllegalArgumentException("ForceLogoffWhenHourExpire must be 0 or 1");
                systemAccess.setForceLogoffWhenHourExpire(forceLogoff);
            }

            // 管理员账户名
            if (json.containsKey("NewAdministratorName")) {
                String adminName = json.getString("NewAdministratorName");
                if (adminName != null && !adminName.trim().isEmpty()) {
                    systemAccess.setNewAdministratorName(adminName.trim());
                }
            }

            // 访客账户名
            if (json.containsKey("NewGuestName")) {
                String guestName = json.getString("NewGuestName");
                if (guestName != null && !guestName.trim().isEmpty()) {
                    systemAccess.setNewGuestName(guestName.trim());
                }
            }

            // 明文密码
            if (json.containsKey("ClearTextPassword")) {
                int clearTextPwd = Integer.parseInt(json.getString("ClearTextPassword"));
                if (clearTextPwd < 0 || clearTextPwd > 1) throw new IllegalArgumentException("ClearTextPassword must be 0 or 1");
                systemAccess.setClearTextPassword(clearTextPwd);
            }

            // LSA匿名名称查找
            if (json.containsKey("LSAAnonymousNameLookup")) {
                int lsaAnonymous = Integer.parseInt(json.getString("LSAAnonymousNameLookup"));
                if (lsaAnonymous < 0 || lsaAnonymous > 1) throw new IllegalArgumentException("LSAAnonymousNameLookup must be 0 or 1");
                systemAccess.setLsaAnonymousNameLookup(lsaAnonymous);
            }

            // 启用管理员账户
            if (json.containsKey("EnableAdminAccount")) {
                int enableAdmin = Integer.parseInt(json.getString("EnableAdminAccount"));
                if (enableAdmin < 0 || enableAdmin > 1) throw new IllegalArgumentException("EnableAdminAccount must be 0 or 1");
                systemAccess.setEnableAdminAccount(enableAdmin);
            }

            // 启用访客账户
            if (json.containsKey("EnableGuestAccount")) {
                int enableGuest = Integer.parseInt(json.getString("EnableGuestAccount"));
                if (enableGuest < 0 || enableGuest > 1) throw new IllegalArgumentException("EnableGuestAccount must be 0 or 1");
                systemAccess.setEnableGuestAccount(enableGuest);
            }

        } catch (Exception e) {
            System.err.println("Error validating system access fields: " + e.getMessage());
            throw e;
        }
    }

    private void processEventAudit(String macAddress, JSONObject eventAuditJson) {
        try {
            EventAudit eventAudit = new EventAudit();
            eventAudit.setMacAddress(macAddress);
            eventAudit.setType("result");

            // 添加数据验证
            validateAndSetEventAuditFields(eventAudit, eventAuditJson);

            // 保存到数据库
            eventAuditMapper.insertSelective(eventAudit);
        } catch (Exception e) {
            System.err.println("处理事件审计数据失败: " + e.getMessage());
            throw e;
        }
    }

    private void validateAndSetEventAuditFields(EventAudit eventAudit, JSONObject json) {
        // 验证和设置所有事件审计字段
        String[] auditFields = {
            "AuditSystemEvents",      // 系统事件审核
            "AuditLogonEvents",       // 登录事件审核
            "AuditObjectAccess",      // 对象访问审核
            "AuditPrivilegeUse",      // 特权使用审核
            "AuditPolicyChange",      // 策略更改审核
            "AuditAccountManage",     // 账户管理审核
            "AuditProcessTracking",   // 进程追踪审核
            "AuditDsAccess",          // 目录服务访问审核
            "AuditAccountLogon"       // 账户登录事件审核
        };

        for (String field : auditFields) {
            try {
                int value = Integer.parseInt(json.getString(field));
                if (value < 0 || value > 3) {
                    throw new IllegalArgumentException(field + " must be between 0 and 3");
                }

                // 使用反射动态设置字段值
                String setterMethod = "set" + field;
                Method method = EventAudit.class.getMethod(setterMethod, Integer.class);
                method.invoke(eventAudit, value);
            } catch (Exception e) {
                System.err.println("Invalid " + field + ": " + e.getMessage());
                try {
                    // 设置为null表示无效值
                    String setterMethod = "set" + field;
                    Method method = EventAudit.class.getMethod(setterMethod, Integer.class);
                    method.invoke(eventAudit, (Integer)null);
                } catch (Exception ex) {
                    System.err.println("Failed to set " + field + " to null: " + ex.getMessage());
                }
            }
        }
    }

    private void processPrivilegeRights(String macAddress, JSONObject privilegeRightsJson) {
        try {
            PrivilegeRights privilegeRights = new PrivilegeRights();
            privilegeRights.setMacAddress(macAddress);
            privilegeRights.setType("result");

            // 添加数据验证
            validateAndSetPrivilegeRightsFields(privilegeRights, privilegeRightsJson);

            // 保存到数据库
            privilegeRightsMapper.insertSelective(privilegeRights);
        } catch (Exception e) {
            System.err.println("处理权限数据失败: " + e.getMessage());
            throw e;
        }
    }

    private void validateAndSetPrivilegeRightsFields(PrivilegeRights privilegeRights, JSONObject json) {
        try {
            // 单进程配置权限
            if (json.containsKey("SeProfileSingleProcessPrivilege")) {
                String singleProcessPrivilege = json.getString("SeProfileSingleProcessPrivilege");
                if (singleProcessPrivilege != null && !singleProcessPrivilege.trim().isEmpty()) {
                    privilegeRights.setSeProfileSingleProcessPrivilege(singleProcessPrivilege.trim());
                }
            }

            // 远程关机权限
            if (json.containsKey("SeRemoteShutdownPrivilege")) {
                String remoteShutdownPrivilege = json.getString("SeRemoteShutdownPrivilege");
                if (remoteShutdownPrivilege != null && !remoteShutdownPrivilege.trim().isEmpty()) {
                    privilegeRights.setSeRemoteShutdownPrivilege(remoteShutdownPrivilege.trim());
                }
            }

            // 本地关机权限
            if (json.containsKey("SeShutdownPrivilege")) {
                String shutdownPrivilege = json.getString("SeShutdownPrivilege");
                if (shutdownPrivilege != null && !shutdownPrivilege.trim().isEmpty()) {
                    privilegeRights.setSeShutdownPrivilege(shutdownPrivilege.trim());
                }
            }

        } catch (Exception e) {
            System.err.println("Error validating privilege rights fields: " + e.getMessage());
            throw e;
        }
    }

    private void processSystemSecurityOption(String macAddress, JSONObject secOptJson) {
        try {
            SystemSecurityOption securityOption = new SystemSecurityOption();
            securityOption.setMacAddress(macAddress);
            securityOption.setType("result");

            // 添加数据验证
            validateAndSetSystemSecurityOptionFields(securityOption, secOptJson);

            // 保存到数据库
            systemSecurityOptionMapper.insertSelective(securityOption);
        } catch (Exception e) {
            System.err.println("处理系统安全选项数据失败: " + e.getMessage());
            throw e;
        }
    }

    private void validateAndSetSystemSecurityOptionFields(SystemSecurityOption securityOption, JSONObject json) {
        try {
            // NoLmHash
            if (json.containsKey("NoLmHash")) {
                Integer noLmHash = json.getInteger("NoLmHash");
                if (noLmHash != null && (noLmHash < 0 || noLmHash > 1)) {
                    throw new IllegalArgumentException("NoLmHash must be 0 or 1");
                }
                securityOption.setNoLmHash(noLmHash);
            }

            // 限制空密码使用
            if (json.containsKey("LimitBlankPasswordUse")) {
                Integer limitBlankPwd = json.getInteger("LimitBlankPasswordUse");
                if (limitBlankPwd != null && (limitBlankPwd < 0 || limitBlankPwd > 1)) {
                    throw new IllegalArgumentException("LimitBlankPasswordUse must be 0 or 1");
                }
                securityOption.setLimitBlankPasswordUse(limitBlankPwd);
            }

            // 限制匿名访问
            if (json.containsKey("RestrictAnonymous")) {
                Integer restrictAnonymous = json.getInteger("RestrictAnonymous");
                if (restrictAnonymous != null && (restrictAnonymous < 0 || restrictAnonymous > 1)) {
                    throw new IllegalArgumentException("RestrictAnonymous must be 0 or 1");
                }
                securityOption.setRestrictAnonymous(restrictAnonymous);
            }

            // 不显示上次登录用户名
            if (json.containsKey("DontDisplayLastUserName")) {
                Integer dontDisplayLastUser = json.getInteger("DontDisplayLastUserName");
                if (dontDisplayLastUser != null && (dontDisplayLastUser < 0 || dontDisplayLastUser > 1)) {
                    throw new IllegalArgumentException("DontDisplayLastUserName must be 0 or 1");
                }
                securityOption.setDontDisplayLastUserName(dontDisplayLastUser);
            }

            // 启用明文密码
            if (json.containsKey("EnablePlainTextPassword")) {
                Integer enablePlainTextPwd = json.getInteger("EnablePlainTextPassword");
                if (enablePlainTextPwd != null && (enablePlainTextPwd < 0 || enablePlainTextPwd > 1)) {
                    throw new IllegalArgumentException("EnablePlainTextPassword must be 0 or 1");
                }
                securityOption.setEnablePlainTextPassword(enablePlainTextPwd);
            }

            // 关机时清除页面文件
            if (json.containsKey("ClearPageFileAtShutdown")) {
                Integer clearPageFile = json.getInteger("ClearPageFileAtShutdown");
                if (clearPageFile != null && (clearPageFile < 0 || clearPageFile > 1)) {
                    throw new IllegalArgumentException("ClearPageFileAtShutdown must be 0 or 1");
                }
                securityOption.setClearPageFileAtShutdown(clearPageFile);
            }

        } catch (Exception e) {
            System.err.println("Error validating system security option fields: " + e.getMessage());
            throw e;
        }
    }

    @Override
    public ResponseResult<Map<String, Object>> getBaselineList(String macAddress, String taskTime, Integer page, Integer limit) {
        try {
            // 计算偏移量
            int offset = (page - 1) * limit;

            // 查询分页数据
            List<BaselineScan> records = baselineScanMapper.selectPageList(macAddress, taskTime, offset, limit);

            // 查询总数
            int total = baselineScanMapper.selectTotalCount(macAddress, taskTime);

            // 构建返回结果
            Map<String, Object> result = new HashMap<>();
            result.put("records", records);
            result.put("total", total);

            return new ResponseResult<>(0, "获取成功", result);
        } catch (Exception e) {
            log.error("获取基线检测列表失败", e);
            return new ResponseResult<>(-1, "获取基线检测列表失败：" + e.getMessage(), null);
        }
    }
}

