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

            // 2. 获取异常项目总数
            String riskSql = "SELECT (" +
                    // 系统访问配置不合格项
                    "SELECT COUNT(*) FROM (" +
                    "  SELECT " +
                    "    CASE " +
                    "      WHEN minimum_password_age > (SELECT minimum_password_age FROM system_access WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN maximum_password_age > (SELECT maximum_password_age FROM system_access WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN minimum_password_length < (SELECT minimum_password_length FROM system_access WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN password_complexity != (SELECT password_complexity FROM system_access WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN password_history_size < (SELECT password_history_size FROM system_access WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN (lockout_bad_count <= 0 OR lockout_bad_count > (SELECT lockout_bad_count FROM system_access WHERE type = 'rule' LIMIT 1)) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN require_logon_to_change_password != (SELECT require_logon_to_change_password FROM system_access WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN force_logoff_when_hour_expire != (SELECT force_logoff_when_hour_expire FROM system_access WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN enable_admin_account != (SELECT enable_admin_account FROM system_access WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN enable_guest_account != (SELECT enable_guest_account FROM system_access WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN clear_text_password != (SELECT clear_text_password FROM system_access WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN lsa_anonymous_name_lookup != (SELECT lsa_anonymous_name_lookup FROM system_access WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END as total_mismatches " +
                    "  FROM system_access " +
                    "  WHERE type = 'result' " +
                    ") t) + " +

                    // 事件审计配置不合格项
                    "(SELECT COUNT(*) FROM (" +
                    "  SELECT " +
                    "    CASE " +
                    "      WHEN audit_system_events != (SELECT audit_system_events FROM event_audit WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN audit_logon_events != (SELECT audit_logon_events FROM event_audit WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN audit_object_access != (SELECT audit_object_access FROM event_audit WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN audit_privilege_use != (SELECT audit_privilege_use FROM event_audit WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN audit_policy_change != (SELECT audit_policy_change FROM event_audit WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN audit_account_manage != (SELECT audit_account_manage FROM event_audit WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN audit_process_tracking != (SELECT audit_process_tracking FROM event_audit WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN audit_DS_access != (SELECT audit_DS_access FROM event_audit WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN audit_account_logon != (SELECT audit_account_logon FROM event_audit WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END as total_mismatches " +
                    "  FROM event_audit " +
                    "  WHERE type = 'result' " +
                    ") t) + " +

                    // 权限配置不合格项
                    "(SELECT COUNT(*) FROM (" +
                    "  SELECT " +
                    "    CASE " +
                    "      WHEN se_profile_single_process_privilege != (SELECT se_profile_single_process_privilege FROM privilege_rights WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN se_remote_shutdown_privilege != (SELECT se_remote_shutdown_privilege FROM privilege_rights WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN se_shutdown_privilege != (SELECT se_shutdown_privilege FROM privilege_rights WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END as total_mismatches " +
                    "  FROM privilege_rights " +
                    "  WHERE type = 'result' " +
                    ") t) + " +

                    // 系统安全选项不合格项
                    "(SELECT COUNT(*) FROM (" +
                    "  SELECT " +
                    "    CASE " +
                    "      WHEN no_LM_hash != (SELECT no_LM_hash FROM system_security_option WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN limit_blank_password_use != (SELECT limit_blank_password_use FROM system_security_option WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN restrict_anonymous != (SELECT restrict_anonymous FROM system_security_option WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN dont_display_last_user_name != (SELECT dont_display_last_user_name FROM system_security_option WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN enable_plain_text_password != (SELECT enable_plain_text_password FROM system_security_option WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END + " +
                    "    CASE " +
                    "      WHEN clear_page_file_at_shutdown != (SELECT clear_page_file_at_shutdown FROM system_security_option WHERE type = 'rule' LIMIT 1) THEN 1 " +
                    "      ELSE 0 " +
                    "    END as total_mismatches " +
                    "  FROM system_security_option " +
                    "  WHERE type = 'result' " +
                    ") t)";

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
                        isPasswordAgeValid(rule.getMinimumPasswordAge(), result.getMinimumPasswordAge(), true),
                        "值必须小于等于规则值", "system_access");
            
            // 密码最长留存期
            addBaselineItem(results, "密码最长留存期",
                        String.valueOf(rule.getMaximumPasswordAge()),
                        String.valueOf(result.getMaximumPasswordAge()),
                        isPasswordAgeValid(rule.getMaximumPasswordAge(), result.getMaximumPasswordAge(), false),
                        "值必须小于等于规则值", "system_access");
            
            // 密码最小长度
            addBaselineItem(results, "密码最小长度",
                        String.valueOf(rule.getMinimumPasswordLength()),
                        String.valueOf(result.getMinimumPasswordLength()),
                        isPasswordLengthValid(rule.getMinimumPasswordLength(), result.getMinimumPasswordLength()),
                        "值必须大于等于规则值", "system_access");
            
            // 密码复杂度要求
            addBaselineItem(results, "密码复杂度要求",
                        String.valueOf(rule.getPasswordComplexity()),
                        String.valueOf(result.getPasswordComplexity()),
                        isBinaryOptionValid(rule.getPasswordComplexity(), result.getPasswordComplexity()),
                        "值必须与规则值相同", "system_access");

                    // 密码历史长度
                    addBaselineItem(results, "密码历史长度",
                        String.valueOf(rule.getPasswordHistorySize()),
                        String.valueOf(result.getPasswordHistorySize()),
                        isPasswordHistoryValid(rule.getPasswordHistorySize(), result.getPasswordHistorySize()),
                        "值必须大于等于规则值", "system_access");

                    // 账户锁定阈值
                    addBaselineItem(results, "账户锁定阈值",
                        String.valueOf(rule.getLockoutBadCount()),
                        String.valueOf(result.getLockoutBadCount()),
                        isLockoutThresholdValid(rule.getLockoutBadCount(), result.getLockoutBadCount()),
                        "值必须大于0且小于等于规则值", "system_access");

                    // 必须登录才能更改密码
                    addBaselineItem(results, "必须登录才能更改密码",
                        String.valueOf(rule.getRequireLogonToChangePassword()),
                        String.valueOf(result.getRequireLogonToChangePassword()),
                        isBinaryOptionValid(rule.getRequireLogonToChangePassword(), result.getRequireLogonToChangePassword()),
                        "值必须与规则值相同", "system_access");

                    // 强制用户在时间到期时注销
                    addBaselineItem(results, "强制用户在时间到期时注销",
                        String.valueOf(rule.getForceLogoffWhenHourExpire()),
                        String.valueOf(result.getForceLogoffWhenHourExpire()),
                        isBinaryOptionValid(rule.getForceLogoffWhenHourExpire(), result.getForceLogoffWhenHourExpire()),
                        "值必须与规则值相同", "system_access");

                    // 管理员账户状态
                    addBaselineItem(results, "管理员账户状态",
                        String.valueOf(rule.getEnableAdminAccount()),
                        String.valueOf(result.getEnableAdminAccount()),
                        isBinaryOptionValid(rule.getEnableAdminAccount(), result.getEnableAdminAccount()),
                        "值必须与规则值相同", "system_access");

                    // 访客账户状态
                    addBaselineItem(results, "访客账户状态",
                        String.valueOf(rule.getEnableGuestAccount()),
                        String.valueOf(result.getEnableGuestAccount()),
                        isBinaryOptionValid(rule.getEnableGuestAccount(), result.getEnableGuestAccount()),
                        "值必须与规则值相同", "system_access");

                    // 明文密码
                    addBaselineItem(results, "明文密码",
                        String.valueOf(rule.getClearTextPassword()),
                        String.valueOf(result.getClearTextPassword()),
                        isBinaryOptionValid(rule.getClearTextPassword(), result.getClearTextPassword()),
                        "值必须与规则值相同", "system_access");

                    // LSA匿名名称查找
                    addBaselineItem(results, "LSA匿名名称查找",
                        String.valueOf(rule.getLsaAnonymousNameLookup()),
                        String.valueOf(result.getLsaAnonymousNameLookup()),
                        isBinaryOptionValid(rule.getLsaAnonymousNameLookup(), result.getLsaAnonymousNameLookup()),
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
                        isAuditSettingValid(rule.getAuditSystemEvents(), result.getAuditSystemEvents()),
                        "值必须大于等于规则值", "event_audit");
            
            // 审核登录事件
            addBaselineItem(results, "审核登录事件",
                        String.valueOf(rule.getAuditLogonEvents()),
                        String.valueOf(result.getAuditLogonEvents()),
                        isAuditSettingValid(rule.getAuditLogonEvents(), result.getAuditLogonEvents()),
                        "值必须大于等于规则值", "event_audit");
            
            // 审核对象访问
            addBaselineItem(results, "审核对象访问",
                        String.valueOf(rule.getAuditObjectAccess()),
                        String.valueOf(result.getAuditObjectAccess()),
                        isAuditSettingValid(rule.getAuditObjectAccess(), result.getAuditObjectAccess()),
                        "值必须大于等于规则值", "event_audit");

                    // 审核特权使用
                    addBaselineItem(results, "审核特权使用",
                        String.valueOf(rule.getAuditPrivilegeUse()),
                        String.valueOf(result.getAuditPrivilegeUse()),
                        isAuditSettingValid(rule.getAuditPrivilegeUse(), result.getAuditPrivilegeUse()),
                        "值必须大于等于规则值", "event_audit");

                    // 审核策略更改
                    addBaselineItem(results, "审核策略更改",
                        String.valueOf(rule.getAuditPolicyChange()),
                        String.valueOf(result.getAuditPolicyChange()),
                        isAuditSettingValid(rule.getAuditPolicyChange(), result.getAuditPolicyChange()),
                        "值必须大于等于规则值", "event_audit");

                    // 审核账户管理
                    addBaselineItem(results, "审核账户管理",
                        String.valueOf(rule.getAuditAccountManage()),
                        String.valueOf(result.getAuditAccountManage()),
                        isAuditSettingValid(rule.getAuditAccountManage(), result.getAuditAccountManage()),
                        "值必须大于等于规则值", "event_audit");

                    // 审核进程追踪
                    addBaselineItem(results, "审核进程追踪",
                        String.valueOf(rule.getAuditProcessTracking()),
                        String.valueOf(result.getAuditProcessTracking()),
                        isAuditSettingValid(rule.getAuditProcessTracking(), result.getAuditProcessTracking()),
                        "值必须大于等于规则值", "event_audit");

                    // 审核目录服务访问
                    addBaselineItem(results, "审核目录服务访问",
                        String.valueOf(rule.getAuditDSAccess()),
                        String.valueOf(result.getAuditDSAccess()),
                        isAuditSettingValid(rule.getAuditDSAccess(), result.getAuditDSAccess()),
                        "值必须大于等于规则值", "event_audit");

                    // 审核账户登录
                    addBaselineItem(results, "审核账户登录",
                        String.valueOf(rule.getAuditAccountLogon()),
                        String.valueOf(result.getAuditAccountLogon()),
                        isAuditSettingValid(rule.getAuditAccountLogon(), result.getAuditAccountLogon()),
                        "值必须大于等于规则值", "event_audit");
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
                        isPrivilegeListValid(rule.getSeProfileSingleProcessPrivilege(), result.getSeProfileSingleProcessPrivilege()),
                        "权限列表必须包含规则值中的所有权限", "privilege_rights");

            // 远程关机权限
            addBaselineItem(results, "远程关机权限",
                        rule.getSeRemoteShutdownPrivilege(),
                        result.getSeRemoteShutdownPrivilege(),
                        isPrivilegeListValid(rule.getSeRemoteShutdownPrivilege(), result.getSeRemoteShutdownPrivilege()),
                        "权限列表必须包含规则值中的所有权限", "privilege_rights");

                    // 本地关机权限
                    addBaselineItem(results, "本地关机权限",
                        rule.getSeShutdownPrivilege(),
                        result.getSeShutdownPrivilege(),
                        isPrivilegeListValid(rule.getSeShutdownPrivilege(), result.getSeShutdownPrivilege()),
                        "权限列表必须包含规则值中的所有权限", "privilege_rights");
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
                        String.valueOf(rule.getNoLMHash()),
                        String.valueOf(result.getNoLMHash()),
                        isBinaryOptionValid(rule.getNoLMHash(), result.getNoLMHash()),
                        "值必须与规则值相同", "system_security_option");
            
            // 限制空密码使用
            addBaselineItem(results, "限制空密码使用",
                        String.valueOf(rule.getLimitBlankPasswordUse()),
                        String.valueOf(result.getLimitBlankPasswordUse()),
                        isBinaryOptionValid(rule.getLimitBlankPasswordUse(), result.getLimitBlankPasswordUse()),
                        "值必须与规则值相同", "system_security_option");
            
            // 限制匿名访问
            addBaselineItem(results, "限制匿名访问",
                        String.valueOf(rule.getRestrictAnonymous()),
                        String.valueOf(result.getRestrictAnonymous()),
                        isBinaryOptionValid(rule.getRestrictAnonymous(), result.getRestrictAnonymous()),
                        "值必须与规则值相同", "system_security_option");

                    // 不显示上次登录用户名
                    addBaselineItem(results, "不显示上次登录用户名",
                        String.valueOf(rule.getDontDisplayLastUserName()),
                        String.valueOf(result.getDontDisplayLastUserName()),
                        isBinaryOptionValid(rule.getDontDisplayLastUserName(), result.getDontDisplayLastUserName()),
                        "值必须与规则值相同", "system_security_option");

                    // 启用明文密码
                    addBaselineItem(results, "启用明文密码",
                        String.valueOf(rule.getEnablePlainTextPassword()),
                        String.valueOf(result.getEnablePlainTextPassword()),
                        isBinaryOptionValid(rule.getEnablePlainTextPassword(), result.getEnablePlainTextPassword()),
                        "值必须与规则值相同", "system_security_option");

                    // 关机时清除页面文件
                    addBaselineItem(results, "关机时清除页面文件",
                        String.valueOf(rule.getClearPageFileAtShutdown()),
                        String.valueOf(result.getClearPageFileAtShutdown()),
                        isBinaryOptionValid(rule.getClearPageFileAtShutdown(), result.getClearPageFileAtShutdown()),
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
            throw e;
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

    private boolean isPasswordAgeValid(Integer standardAge, Integer actualAge, boolean isMinimum) {
        if (standardAge == null || actualAge == null) return false;
        return isMinimum ? 
            actualAge <= standardAge : 
            actualAge <= standardAge;   
    }

    private boolean isPasswordLengthValid(Integer standardLength, Integer actualLength) {
        if (standardLength == null || actualLength == null) return false;
        return actualLength >= standardLength;  // 密码长度必须大于等于标准值
    }

    private boolean isPasswordHistoryValid(Integer standardSize, Integer actualSize) {
        if (standardSize == null || actualSize == null) return false;
        return actualSize >= standardSize;  // 密码历史必须大于等于标准值
    }

    private boolean isLockoutThresholdValid(Integer standardCount, Integer actualCount) {
        if (standardCount == null || actualCount == null) return false;
        return actualCount > 0 && actualCount <= standardCount;  // 必须大于0且小于等于标准值
    }

    private boolean isBinaryOptionValid(Integer standardOption, Integer actualOption) {
        if (standardOption == null || actualOption == null) return false;
        return standardOption.equals(actualOption);  // 二进制选项必须完全匹配
    }

    private boolean isAuditSettingValid(Integer standardSetting, Integer actualSetting) {
        if (standardSetting == null || actualSetting == null) return false;
        return actualSetting >= standardSetting;  // 审计设置必须大于等于标准值
    }

    private boolean isPrivilegeListValid(String standardList, String actualList) {
    if (standardList == null || actualList == null) return false;
    
    List<String> standardItems = Arrays.asList(standardList.replace("[", "").replace("]", "").split(",\\s*"));
        List<String> actualItems = Arrays.asList(actualList.replace("[", "").replace("]", "").split(",\\s*"));

    // 检查两个列表是否完全相等（忽略顺序）
    return standardItems.size() == actualItems.size() && 
           standardItems.containsAll(actualItems) && 
           actualItems.containsAll(standardItems);
    }

    @Override
    public void processBaselineData(Map<String, Object> data) {
        try {
            String macAddress = (String) data.get("macAddress");
            JSONObject baselineData = (JSONObject) data.get("baselineData");

            // 打印接收到的原始数据
            log.info("Received baseline data for MAC {}: {}", macAddress, baselineData);

            // 处理系统访问配置
            if (baselineData.containsKey("system_access")) {
                JSONObject sysAccessJson = baselineData.getJSONObject("system_access");
                processSystemAccess(macAddress, sysAccessJson);
            }

            // 处理事件审计配置
            if (baselineData.containsKey("event_audit")) {
                JSONObject eventAuditJson = baselineData.getJSONObject("event_audit");
                // 打印事件审计数据
                log.info("Processing event audit data: {}", eventAuditJson);
                
                EventAudit eventAudit = new EventAudit();
                eventAudit.setMacAddress(macAddress);
                eventAudit.setType("result");

                // 确保大写DS
                if (eventAuditJson.containsKey("AuditDSAccess")) {
                    Integer auditDSAccess = eventAuditJson.getInteger("AuditDSAccess");
                    log.info("Setting AuditDSAccess value: {}", auditDSAccess);
                    eventAudit.setAuditDSAccess(auditDSAccess);
                }

                // 设置其他审计字段
                if (eventAuditJson.containsKey("AuditSystemEvents")) {
                    eventAudit.setAuditSystemEvents(eventAuditJson.getInteger("AuditSystemEvents"));
                }
                if (eventAuditJson.containsKey("AuditLogonEvents")) {
                    eventAudit.setAuditLogonEvents(eventAuditJson.getInteger("AuditLogonEvents"));
                }
                if (eventAuditJson.containsKey("AuditObjectAccess")) {
                    eventAudit.setAuditObjectAccess(eventAuditJson.getInteger("AuditObjectAccess"));
                }
                if (eventAuditJson.containsKey("AuditPrivilegeUse")) {
                    eventAudit.setAuditPrivilegeUse(eventAuditJson.getInteger("AuditPrivilegeUse"));
                }
                if (eventAuditJson.containsKey("AuditPolicyChange")) {
                    eventAudit.setAuditPolicyChange(eventAuditJson.getInteger("AuditPolicyChange"));
                }
                if (eventAuditJson.containsKey("AuditAccountManage")) {
                    eventAudit.setAuditAccountManage(eventAuditJson.getInteger("AuditAccountManage"));
                }
                if (eventAuditJson.containsKey("AuditProcessTracking")) {
                    eventAudit.setAuditProcessTracking(eventAuditJson.getInteger("AuditProcessTracking"));
                }
                if (eventAuditJson.containsKey("AuditAccountLogon")) {
                    eventAudit.setAuditAccountLogon(eventAuditJson.getInteger("AuditAccountLogon"));
                }

                // 实现 upsert 操作
                List<EventAudit> existingRecords = eventAuditMapper.selectByTypeAndMac("result", macAddress);
                if (!existingRecords.isEmpty()) {
                    EventAudit existingRecord = existingRecords.get(0);
                    eventAudit.setEventAuditId(existingRecord.getEventAuditId());
                    log.info("Updating event audit record for MAC: {}, AuditDSAccess: {}", macAddress, eventAudit.getAuditDSAccess());
                    eventAuditMapper.updateByPrimaryKeySelective(eventAudit);
                } else {
                    log.info("Inserting new event audit record for MAC: {}, AuditDSAccess: {}", macAddress, eventAudit.getAuditDSAccess());
                    eventAuditMapper.insertSelective(eventAudit);
                }
            }

            // 处理权限配置
            if (baselineData.containsKey("privilege_rights")) {
                JSONObject privilegeRightsJson = baselineData.getJSONObject("privilege_rights");
                processPrivilegeRights(macAddress, privilegeRightsJson);
            }

            // 处理系统安全选项
            if (baselineData.containsKey("system_security_option")) {
                JSONObject secOptJson = baselineData.getJSONObject("system_security_option");
                // 打印系统安全选项数据
                log.info("Processing system security option data: {}", secOptJson);
                
                SystemSecurityOption securityOption = new SystemSecurityOption();
                securityOption.setMacAddress(macAddress);
                securityOption.setType("result");

                // 确保大写LM
                if (secOptJson.containsKey("NoLMHash")) {
                    Integer noLMHash = secOptJson.getInteger("NoLMHash");
                    log.info("Setting NoLMHash value: {}", noLMHash);
                    securityOption.setNoLMHash(noLMHash);
                }

                // 设置其他字段
                if (secOptJson.containsKey("LimitBlankPasswordUse")) {
                    securityOption.setLimitBlankPasswordUse(secOptJson.getInteger("LimitBlankPasswordUse"));
                }
                if (secOptJson.containsKey("RestrictAnonymous")) {
                    securityOption.setRestrictAnonymous(secOptJson.getInteger("RestrictAnonymous"));
                }
                if (secOptJson.containsKey("DontDisplayLastUserName")) {
                    securityOption.setDontDisplayLastUserName(secOptJson.getInteger("DontDisplayLastUserName"));
                }
                if (secOptJson.containsKey("EnablePlainTextPassword")) {
                    securityOption.setEnablePlainTextPassword(secOptJson.getInteger("EnablePlainTextPassword"));
                }
                if (secOptJson.containsKey("ClearPageFileAtShutdown")) {
                    securityOption.setClearPageFileAtShutdown(secOptJson.getInteger("ClearPageFileAtShutdown"));
                }

                // 实现 upsert 操作
                List<SystemSecurityOption> existingRecords = systemSecurityOptionMapper.selectByTypeAndMac("result", macAddress);
                if (!existingRecords.isEmpty()) {
                    SystemSecurityOption existingRecord = existingRecords.get(0);
                    securityOption.setSystemSecurityOptionId(existingRecord.getSystemSecurityOptionId());
                    log.info("Updating system security option for MAC: {}, NoLMHash: {}", macAddress, securityOption.getNoLMHash());
                    systemSecurityOptionMapper.updateByPrimaryKeySelective(securityOption);
            } else {
                    log.info("Inserting new system security option for MAC: {}, NoLMHash: {}", macAddress, securityOption.getNoLMHash());
                    systemSecurityOptionMapper.insertSelective(securityOption);
                }
            }
        } catch (Exception e) {
            log.error("处理基线数据失败: {}", e.getMessage(), e);
            throw e;
        }
    }

    private void processSystemAccess(String macAddress, JSONObject sysAccessJson) {
        try {
            SystemAccess systemAccess = new SystemAccess();
            systemAccess.setMacAddress(macAddress);
            systemAccess.setType("result");

            // 添加数据验证
            validateAndSetSystemAccessFields(systemAccess, sysAccessJson);

            // 查询是否存在相同MAC地址的记录
            List<SystemAccess> existingRecords = systemAccessMapper.selectByTypeAndMac("result", macAddress);
            
            if (!existingRecords.isEmpty()) {
                // 存在记录，执行更新
                SystemAccess existingRecord = existingRecords.get(0);
                systemAccess.setSystemAccessId(existingRecord.getSystemAccessId());
                systemAccessMapper.updateByPrimaryKeySelective(systemAccess);
            } else {
                // 不存在记录，执行插入
            systemAccessMapper.insertSelective(systemAccess);
            }
        } catch (Exception e) {
            log.error("处理系统访问数据失败: {}", e.getMessage(), e);
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

            // 处理 AuditDSAccess 字段
            if (eventAuditJson.containsKey("AuditDSAccess")) {
                Integer auditDSAccess = eventAuditJson.getInteger("AuditDSAccess");
                eventAudit.setAuditDSAccess(auditDSAccess);
            }

            // 处理其他审计字段
            if (eventAuditJson.containsKey("AuditSystemEvents")) {
                eventAudit.setAuditSystemEvents(eventAuditJson.getInteger("AuditSystemEvents"));
            }
            if (eventAuditJson.containsKey("AuditLogonEvents")) {
                eventAudit.setAuditLogonEvents(eventAuditJson.getInteger("AuditLogonEvents"));
            }
            if (eventAuditJson.containsKey("AuditObjectAccess")) {
                eventAudit.setAuditObjectAccess(eventAuditJson.getInteger("AuditObjectAccess"));
            }
            if (eventAuditJson.containsKey("AuditPrivilegeUse")) {
                eventAudit.setAuditPrivilegeUse(eventAuditJson.getInteger("AuditPrivilegeUse"));
            }
            if (eventAuditJson.containsKey("AuditPolicyChange")) {
                eventAudit.setAuditPolicyChange(eventAuditJson.getInteger("AuditPolicyChange"));
            }
            if (eventAuditJson.containsKey("AuditAccountManage")) {
                eventAudit.setAuditAccountManage(eventAuditJson.getInteger("AuditAccountManage"));
            }
            if (eventAuditJson.containsKey("AuditProcessTracking")) {
                eventAudit.setAuditProcessTracking(eventAuditJson.getInteger("AuditProcessTracking"));
            }
            if (eventAuditJson.containsKey("AuditAccountLogon")) {
                eventAudit.setAuditAccountLogon(eventAuditJson.getInteger("AuditAccountLogon"));
            }

            // 实现 upsert 操作
            List<EventAudit> existingRecords = eventAuditMapper.selectByTypeAndMac("result", macAddress);
            
            if (!existingRecords.isEmpty()) {
                EventAudit existingRecord = existingRecords.get(0);
                eventAudit.setEventAuditId(existingRecord.getEventAuditId());
                eventAuditMapper.updateByPrimaryKeySelective(eventAudit);
                log.info("Updated event audit for MAC: {}, AuditDSAccess: {}", macAddress, eventAudit.getAuditDSAccess());
            } else {
            eventAuditMapper.insertSelective(eventAudit);
                log.info("Inserted new event audit for MAC: {}, AuditDSAccess: {}", macAddress, eventAudit.getAuditDSAccess());
            }
        } catch (Exception e) {
            log.error("处理事件审计数据失败: {}", e.getMessage(), e);
            throw e;
        }
    }

    private void processPrivilegeRights(String macAddress, JSONObject privilegeRightsJson) {
        try {
            PrivilegeRights privilegeRights = new PrivilegeRights();
            privilegeRights.setMacAddress(macAddress);
            privilegeRights.setType("result");

            // 添加数据验证
            validateAndSetPrivilegeRightsFields(privilegeRights, privilegeRightsJson);

            // 查询是否存在相同MAC地址的记录
            List<PrivilegeRights> existingRecords = privilegeRightsMapper.selectByTypeAndMac("result", macAddress);
            
            if (!existingRecords.isEmpty()) {
                // 存在记录，执行更新
                PrivilegeRights existingRecord = existingRecords.get(0);
                privilegeRights.setPrivilegeRightsId(existingRecord.getPrivilegeRightsId());
                privilegeRightsMapper.updateByPrimaryKeySelective(privilegeRights);
            } else {
                // 不存在记录，执行插入
            privilegeRightsMapper.insertSelective(privilegeRights);
            }
        } catch (Exception e) {
            log.error("处理权限数据失败: {}", e.getMessage(), e);
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

            // 处理 NoLMHash 字段
            if (secOptJson.containsKey("NoLMHash")) {
                Integer noLMHash = secOptJson.getInteger("NoLMHash");
                securityOption.setNoLMHash(noLMHash);
            }

            // 处理其他字段
            if (secOptJson.containsKey("LimitBlankPasswordUse")) {
                securityOption.setLimitBlankPasswordUse(secOptJson.getInteger("LimitBlankPasswordUse"));
            }
            if (secOptJson.containsKey("RestrictAnonymous")) {
                securityOption.setRestrictAnonymous(secOptJson.getInteger("RestrictAnonymous"));
            }
            if (secOptJson.containsKey("DontDisplayLastUserName")) {
                securityOption.setDontDisplayLastUserName(secOptJson.getInteger("DontDisplayLastUserName"));
            }
            if (secOptJson.containsKey("EnablePlainTextPassword")) {
                securityOption.setEnablePlainTextPassword(secOptJson.getInteger("EnablePlainTextPassword"));
            }
            if (secOptJson.containsKey("ClearPageFileAtShutdown")) {
                securityOption.setClearPageFileAtShutdown(secOptJson.getInteger("ClearPageFileAtShutdown"));
            }

            // 实现 upsert 操作
            List<SystemSecurityOption> existingRecords = systemSecurityOptionMapper.selectByTypeAndMac("result", macAddress);
            
            if (!existingRecords.isEmpty()) {
                SystemSecurityOption existingRecord = existingRecords.get(0);
                securityOption.setSystemSecurityOptionId(existingRecord.getSystemSecurityOptionId());
                systemSecurityOptionMapper.updateByPrimaryKeySelective(securityOption);
                log.info("Updated system security option for MAC: {}, NoLMHash: {}", macAddress, securityOption.getNoLMHash());
            } else {
            systemSecurityOptionMapper.insertSelective(securityOption);
                log.info("Inserted new system security option for MAC: {}, NoLMHash: {}", macAddress, securityOption.getNoLMHash());
            }
        } catch (Exception e) {
            log.error("处理系统安全选项数据失败: {}", e.getMessage(), e);
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

