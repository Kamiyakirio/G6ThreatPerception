package com.tpp.threat_perception_platform.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.rabbitmq.client.Channel;
import com.tpp.threat_perception_platform.asset.Account;
import com.tpp.threat_perception_platform.asset.App;
import com.tpp.threat_perception_platform.asset.Process;
import com.tpp.threat_perception_platform.asset.Service;
import com.tpp.threat_perception_platform.dao.*;
import com.tpp.threat_perception_platform.pojo.*;
import com.tpp.threat_perception_platform.service.BaselineService;
import com.tpp.threat_perception_platform.service.RabbitMQService;
import com.tpp.threat_perception_platform.service.AIService;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

@Component
public class RabbitMQController {

    @Autowired private HostMapper hostMapper;
    @Autowired private AccountMapper accountMapper;
    @Autowired private AppMapper appMapper;
    @Autowired private ProcessMapper processMapper;
    @Autowired private ServiceMapper serviceMapper;
    @Autowired private RiskMapper riskMapper;
    @Autowired private VulScanMapper vulScanMapper;
    @Autowired private AppRiskResultMapper appRiskResultMapper;
    @Autowired private LogMapper logMapper;
    @Autowired private AIService aiService;
    @Autowired private LogScanMapper logScanMapper;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private SystemAccessMapper systemAccessMapper;
    @Autowired private EventAuditMapper eventAuditMapper;
    @Autowired private PrivilegeRightsMapper privilegeRightsMapper;
    @Autowired private SystemSecurityOptionMapper systemSecurityOptionMapper;
    @Autowired private BaselineScanMapper baselineScanMapper;
    @Autowired private BaselineService baselineService;
    @Autowired private RabbitMQService rabbitMQService;


    // 辅助方法：清理和解析AI返回的JSON
    private JSONObject parseAIResult(String aiResult) throws Exception {
        if (aiResult == null || aiResult.trim().isEmpty()) {
            throw new Exception("AI分析结果为空");
        }

        String cleanedJson = aiResult.trim();

        // 移除可能的代码块标记
        if (cleanedJson.startsWith("```json")) {
            cleanedJson = cleanedJson.substring(7);
        } else if (cleanedJson.startsWith("```")) {
            cleanedJson = cleanedJson.substring(3);
        }

        if (cleanedJson.endsWith("```")) {
            cleanedJson = cleanedJson.substring(0, cleanedJson.length() - 3);
        }

        cleanedJson = cleanedJson.trim();

        // 尝试解析JSON
        try {
            return JSON.parseObject(cleanedJson);
        } catch (Exception e) {
            // 如果解析失败，尝试查找JSON对象
            int startBrace = cleanedJson.indexOf('{');
            int endBrace = cleanedJson.lastIndexOf('}');

            if (startBrace >= 0 && endBrace > startBrace) {
                String jsonPart = cleanedJson.substring(startBrace, endBrace + 1);
                return JSON.parseObject(jsonPart);
            }

            throw new Exception("无法解析AI分析结果: " + e.getMessage());
        }
    }

    // 获取下一个 detectId
    private int getNextDetectId(String macAddress, AccountMapper mapper) {
        Integer lastId = mapper.selectLastDetectIdByMac(macAddress);
        return (lastId == null) ? 0 : lastId + 1;
    }
    private int getNextDetectId(String macAddress, AppMapper mapper) {
        Integer lastId = mapper.selectLastDetectIdByMac(macAddress);
        return (lastId == null) ? 0 : lastId + 1;
    }
    private int getNextDetectId(String macAddress, ServiceMapper mapper) {
        Integer lastId = mapper.selectLastDetectIdByMac(macAddress);
        return (lastId == null) ? 0 : lastId + 1;
    }
    private int getNextDetectId(String macAddress, ProcessMapper mapper) {
        Integer lastId = mapper.selectLastDetectIdByMac(macAddress);
        return (lastId == null) ? 0 : lastId + 1;
    }
    private int getNextDetectIdForAppRisk(String hostIdentifier) {
        Integer lastId = appRiskResultMapper.selectLastDetectIdByHostIdentifier(hostIdentifier);
        return (lastId == null) ? 0 : lastId + 1;
    }

    @RabbitListener(queues = "hello")
    public void receiveHostInfo(Message message, Channel channel) throws IOException {
        long tag = message.getMessageProperties().getDeliveryTag();
        try {
            String messageBody = new String(message.getBody());
//            System.out.println("收到主机信息消息: " + messageBody);

            Host host = new Host();
            HashMap<String, Object> dataDict = JSON.parseObject(messageBody, HashMap.class);

            host.setMacAddress(dataDict.get("macAddress").toString());
            host.setHostName(dataDict.get("pcName").toString());
            host.setIpAddress(dataDict.get("ipAddress").toString());
            host.setOsType(dataDict.get("osName").toString());
            host.setOsName(dataDict.get("osName").toString() + " " + dataDict.get("osNameDetailed").toString());
            host.setCpuName(dataDict.get("cpuInfo").toString());
            host.setOsBit(dataDict.get("osBit").toString());
            host.setRam(dataDict.get("memorySize").toString());

            Host savedResult = hostMapper.selectByMacAddress(host.getMacAddress());
            if (savedResult != null) {
                host.setUpdateTime(new Date(System.currentTimeMillis()));
                host.setId(savedResult.getId());
                hostMapper.updateByPrimaryKeySelective(host);
            } else {
                host.setCreateTime(new Date(System.currentTimeMillis()));
                hostMapper.insert(host);
            }

            channel.basicAck(tag, false);
            System.out.println("主机信息处理成功");
        } catch (Exception e) {
//            System.out.println("处理主机信息失败: " + e.getMessage());
            e.printStackTrace();
            channel.basicNack(tag, false, true);
        }
    }

    @RabbitListener(queues = "detect_result")
    public void receiveDetectResult(String messageBody, Message message, Channel channel) throws IOException {
        long deliveryTag = message.getMessageProperties().getDeliveryTag();

        try {
            JSONObject fullData = JSON.parseObject(new String(message.getBody(), StandardCharsets.UTF_8));
            JSONObject info = fullData.getJSONObject("info");
            JSONArray dataList = fullData.getJSONArray("data");

            String hostName = info.getString("hostName");
            String macAddress = info.getString("macAddress");
            String timeStr = info.getString("time");
            Integer id = info.getInteger("id");

            Date time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(timeStr);

            for (int i = 0; i < dataList.size(); i++) {
                JSONObject dataItem = dataList.getJSONObject(i);
                String dataType = dataItem.getString("type");

                if ("account".equalsIgnoreCase(dataType)) {
                    JSONArray accountsArray = dataItem.getJSONArray("data");
                    int detectId = getNextDetectId(macAddress, accountMapper);
                    for (int j = 0; j < accountsArray.size(); j++) {
                        JSONObject accountData = accountsArray.getJSONObject(j);
                        Account account = new Account();
                        account.setDetectId(detectId);
                        account.setHostName(hostName);
                        account.setMacAddress(macAddress);
                        account.setTime(time);
                        account.setId(id);
                        account.setName(accountData.getString("name"));
                        account.setFullName(accountData.getString("full_name"));
                        account.setSid(accountData.getString("sid"));
                        account.setSidType(accountData.getInteger("sid_type"));
                        account.setStatus(accountData.getString("status"));
                        account.setDisabled(Boolean.TRUE.equals(accountData.getBoolean("disabled")) ? 1 : 0);
                        account.setLockout(Boolean.TRUE.equals(accountData.getBoolean("lockout")) ? 1 : 0);
                        account.setPasswordChangeable(Boolean.TRUE.equals(accountData.getBoolean("password_changeable")) ? 1 : 0);
                        account.setPasswordExpires(Boolean.TRUE.equals(accountData.getBoolean("password_expires")) ? 1 : 0);
                        account.setPasswordRequired(Boolean.TRUE.equals(accountData.getBoolean("password_required")) ? 1 : 0);


                        accountMapper.insertSelective(account);
                    }
                }

                if ("app".equalsIgnoreCase(dataType)) {
                    JSONArray appsArray = dataItem.getJSONArray("data");
                    int detectId = getNextDetectId(macAddress, appMapper);
                    for (int j = 0; j < appsArray.size(); j++) {
                        JSONObject appData = appsArray.getJSONObject(j);
                        App app = new App();
                        app.setDetectId(detectId);
                        app.setHostName(hostName);
                        app.setMacAddress(macAddress);
                        app.setTime(time);
                        app.setId(id);
                        app.setDisplayName(appData.getString("display_name"));
                        app.setInstallLocation(appData.getString("install_location"));
                        app.setUninstallString(appData.getString("uninstall_string"));
                        appMapper.insertSelective(app);
                    }
                }

                if ("process".equalsIgnoreCase(dataType)) {
                    JSONArray processesArray = dataItem.getJSONArray("data");
                    int detectId = getNextDetectId(macAddress, processMapper);
                    for (int j = 0; j < processesArray.size(); j++) {
                        JSONObject processData = processesArray.getJSONObject(j);
                        Process process = new Process();
                        process.setDetectId(detectId);
                        process.setHostName(hostName);
                        process.setMacAddress(macAddress);
                        process.setTime(time);
                        process.setId(id);
                        process.setPid(processData.getInteger("pid"));
                        process.setPpid(processData.getInteger("ppid"));
                        process.setName(processData.getString("name"));
                        process.setCmd(processData.getString("cmd"));
                        process.setPriority(processData.getInteger("priority"));
                        process.setDescription(processData.getString("description"));

                        processMapper.insertSelective(process);
                    }
                }

                if ("service".equalsIgnoreCase(dataType)) {
                    JSONArray servicesArray = dataItem.getJSONArray("data");
                    int detectId = getNextDetectId(macAddress, serviceMapper);
                    for (int j = 0; j < servicesArray.size(); j++) {
                        JSONObject serviceData = servicesArray.getJSONObject(j);
                        Service service = new Service();
                        service.setDetectId(detectId);
                        service.setHostName(hostName);
                        service.setMacAddress(macAddress);
                        service.setTime(time);
                        service.setId(id);
                        service.setProtocol(serviceData.getString("protocol"));
                        service.setPort(serviceData.getInteger("port"));
                        service.setState(serviceData.getString("state"));
                        service.setName(serviceData.getString("name"));
                        service.setProduct(serviceData.getString("product"));
                        service.setVersion(serviceData.getString("version"));
                        service.setExtrainfo(serviceData.getString("extrainfo"));


                        serviceMapper.insertSelective(service);
                    }
                }
            }

            channel.basicAck(deliveryTag, false);
        } catch (Exception e) {
            channel.basicAck(deliveryTag, false);
        }
    }

    @RabbitListener(queues = "apprisk_detect_result")
    public void receiveAppRiskDetectResult(String messageBody, Message message, Channel channel) throws IOException {
        long deliveryTag = message.getMessageProperties().getDeliveryTag();
//        System.out.println("收到应用风险探测结果: " + messageBody);

        try {
            JSONObject jsonObject = JSON.parseObject(new String(message.getBody(),StandardCharsets.UTF_8));
            JSONObject info = jsonObject.getJSONObject("info");
            JSONArray data = jsonObject.getJSONArray("data");

            String macAddress = info.getString("macAddress");
            String hostIdentifier = info.getString("hostIdentifier");

            if (data != null && !data.isEmpty()) {
                for (int i = 0; i < data.size(); i++) {
                    JSONObject riskData = data.getJSONObject(i);
                    AppRiskResult result = new AppRiskResult();
                    result.setHostIdentifier(hostIdentifier);
                    result.setMacAddress(macAddress);
                    result.setAppriskId(riskData.getInteger("appriskId"));
                    result.setIsVulnerable(riskData.getByte("isVulnerable"));
                    result.setResultEvidence(riskData.getString("resultEvidence"));
                    result.setDetectedAt(new Date());
                    appRiskResultMapper.insertSelective(result);
                }
//                System.out.println("应用风险探测结果已保存到数据库");
            }

            channel.basicAck(deliveryTag, false);
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("处理应用风险探测结果失败: " + e.getMessage());
            channel.basicAck(deliveryTag, false);
        }
    }

    @RabbitListener(queues = "pwd_detect_result")
    public void receivePwdDetectResult(String messageBody, Message message, Channel channel) throws IOException {
//        System.out.println("接收到密码检测结果：" + messageBody);
        long deliveryTag = message.getMessageProperties().getDeliveryTag();

        try {
            JSONObject fullData = JSON.parseObject(new String(message.getBody(),StandardCharsets.UTF_8));
            JSONObject info = fullData.getJSONObject("info");
            JSONArray dataList = fullData.getJSONArray("data");

            for (int i = 0; i < dataList.size(); i++) {
                JSONObject dataItem = dataList.getJSONObject(i);
                String dataType = dataItem.getString("type");
                if (Objects.equals(dataType, "password")) {
                    JSONArray pwdAccountsArray = dataItem.getJSONArray("data");

                    for (int j = 0; j < pwdAccountsArray.size(); j++) {
                        JSONObject accountData = pwdAccountsArray.getJSONObject(j);
                        Risk risk = new Risk();
                        risk.setRiskType("account");
                        risk.setRiskDesc("有弱口令风险");
                        risk.setRe(accountData.getString("name"));
                        System.out.println("risk: " + risk);
                        riskMapper.insertSelective(risk);
                    }
                }
            }

            channel.basicAck(deliveryTag, false);
        } catch (Exception e) {
            e.printStackTrace();
            channel.basicAck(deliveryTag, false);
        }
    }

    @RabbitListener(queues = "vul_scan_result")
    public void vul_scan_result(String messageBody, Message message, Channel channel) throws IOException {
        long deliveryTag = message.getMessageProperties().getDeliveryTag();

        try {
            JSONObject fullData = JSON.parseObject(new String(message.getBody(),StandardCharsets.UTF_8));
            JSONObject info = fullData.getJSONObject("info");
            JSONArray dataList = fullData.getJSONArray("data");

            String macAddress = info.getString("macAddress");
            String timeStr = info.getString("time");
            Date time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(timeStr);

            for (int i = 0; i < dataList.size(); i++) {
                JSONObject data = dataList.getJSONObject(i);
                VulScan vulScan = new VulScan();
                vulScan.setVulId(data.getInteger("id"));
                vulScan.setResultCode(data.getInteger("code"));
                vulScan.setMacAddress(macAddress);
                vulScan.setResultDesc(data.getString("message"));
                vulScan.setTime(time);

                VulScan dbVulscan = vulScanMapper.selectByMacAddressAndVulId(macAddress, (long) data.getInteger("id"));
                if (dbVulscan == null) {
                    vulScanMapper.insertSelective(vulScan);
                } else if (!dbVulscan.equals(vulScan)) {
                    vulScan.setId(dbVulscan.getId());
                    vulScanMapper.updateByPrimaryKeySelective(vulScan);
                }
            }

            channel.basicAck(deliveryTag, false);
        } catch (Exception e) {
            e.printStackTrace();
            channel.basicAck(deliveryTag, false);
        }
    }
        @RabbitListener(queues = "log_detect_result")
        public void receiveLogDetectResult(String messageBody, Message message, Channel channel) throws IOException {
            long deliveryTag = message.getMessageProperties().getDeliveryTag();
            try {
                // 1. 解析消息体
                JSONObject fullData = JSON.parseObject(new String(message.getBody(), StandardCharsets.UTF_8));
                JSONObject info = fullData.getJSONObject("info");
                JSONArray dataList = fullData.getJSONArray("data");

                String macAddress = info.getString("macAddress");
                String hostName = info.getString("hostName");
                Integer infoId = info.getInteger("id");
                String timeStr = info.getString("time");

                String beginTimeStr=info.getString("startTime");
                String endTimeStr=info.getString("endTime");
                Date beginTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(beginTimeStr);
                Date endTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(endTimeStr);

                Date time = null;
                try {
                    time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(timeStr);
                } catch (Exception e) {
//                    System.err.println("解析info.time失败: " + timeStr + ", 错误: " + e.getMessage());
                }

                // 收集所有日志用于AI分析
                List<Log> logsToAnalyze = new ArrayList<>();
                List<Log> savedLogs = new ArrayList<>();

                LogScan logScan = new LogScan();
                logScan.setMacAddress(macAddress);
                logScan.setHostName(hostName);
                logScan.setStartTime(beginTime);
                logScan.setEndTime(endTime);
                String logScanUUID=UUID.randomUUID().toString();
                logScan.setUuid(logScanUUID);

                logScanMapper.insertSelective(logScan);
                String sql="SELECT * from log_scan WHERE uuid = ?";
                logScan=jdbcTemplate.queryForObject(sql, new BeanPropertyRowMapper<>(LogScan.class),logScanUUID);
                Integer logScanId=logScan.getId();

                for (int i = 0; i < dataList.size(); i++) {
                    JSONObject dataItem = dataList.getJSONObject(i);
                    String dataType = dataItem.getString("type");
                    if ("log".equalsIgnoreCase(dataType)) {
                        JSONArray logsArray = dataItem.getJSONArray("data");
                        for (int j = 0; j < logsArray.size(); j++) {
                            JSONObject logData = logsArray.getJSONObject(j);
                            Log log = new Log();
                            log.setMacAddress(macAddress);
                            log.setHostName(hostName);
                            log.setId(infoId);
                            log.setTime(time); // 使用info中的time

                            // event_id
                            Integer eventId = logData.getInteger("event_id");
                            if (eventId == null && logData.containsKey("eventId")) {
                                eventId = logData.getInteger("eventId");
                            }
                            log.setEventId(eventId);

                            // risk_level (agent提供的风险等级)
                            Integer agentRiskLevel = logData.getInteger("risk_level");
                            log.setRiskLevel(agentRiskLevel);

                            // timestamp - 解析日志中的timestamp字段
                            String timestampStr = logData.getString("timestamp");
                            if (timestampStr != null) {
                                try {
                                    // 移除UTC后缀并解析
                                    String cleanTimestamp = timestampStr.replace(" UTC", "");
                                    Date timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSSSSS").parse(cleanTimestamp);
                                    log.setTimestamp(timestamp);
                                } catch (Exception e) {
                                    try {
                                        // 尝试不带毫秒的格式
                                        String cleanTimestamp = timestampStr.replace(" UTC", "");
                                        Date timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(cleanTimestamp);
                                        log.setTimestamp(timestamp);
                                    } catch (Exception e2) {
//                                        System.err.println("解析timestamp失败: " + timestampStr + ", 错误: " + e2.getMessage());
                                        log.setTimestamp(null);
                                    }
                                }
                            }

                            // risk_desc
                            log.setRiskDesc(logData.getString("risk_desc"));

                            // channel
                            log.setChannel(logData.getString("channel"));

                            // event_data
                            Object eventData = logData.get("event_data");
                            if (eventData != null) {
                                log.setEventData(JSON.toJSONString(eventData));
                            }

                            log.setLogScanId(logScanId);

                            // 避免重复插入
                            Log existingLog = logMapper.selectByMacAddressAndEventIdAndTimestampAndChannel(
                                    log.getMacAddress(), log.getEventId(), log.getTimestamp(), log.getChannel());
                            if (existingLog == null) {
                                logMapper.insertSelective(log);
                                savedLogs.add(log);
                                logsToAnalyze.add(log);
//                            System.out.println("日志记录已保存到数据库");
                            } else {
//                                System.out.println("相同的日志记录已存在，跳过保存");
                            }
                        }
                    }
                }

                channel.basicAck(deliveryTag, false);
            } catch (Exception e) {
                e.printStackTrace();
//                System.err.println("处理日志探测结果失败: " + e.getMessage());
                channel.basicAck(deliveryTag, false);
            }
        }


    @RabbitListener(queues = "baseline_detect_result")
    public void receiveBaselineDetectResult(String messageBody, Message message, Channel channel) throws IOException {
        long deliveryTag = message.getMessageProperties().getDeliveryTag();
        try {
            JSONObject fullData = JSON.parseObject(new String(message.getBody(), StandardCharsets.UTF_8));
            JSONArray dataList = fullData.getJSONArray("data");
            JSONObject info = fullData.getJSONObject("info");

            String macAddress = info.getString("macAddress");
            String hostName = info.getString("hostName");

            // 检查是否是修复消息
            if (dataList != null && dataList.size() > 0) {
                JSONObject firstData = dataList.getJSONObject(0);
                if ("baseline_repair".equals(firstData.getString("type")) && "success".equals(firstData.getString("data"))) {
                    String id = info.getString("id");

                    // 等待5秒后执行重新检测
                    Thread.sleep(5000);

                    // 构建检测消息
                    Map<String, Object> detectData = new HashMap<>();
                    detectData.put("hostName", hostName);
                    detectData.put("macAddress", macAddress);
                    detectData.put("id", id);
                    detectData.put("type", "baseline");
                    detectData.put("baselineTask", true);

                    // 发送检测命令到对应的agent队列
                    String queueName = "agentQueue" + macAddress.replace(":", "");
//                    System.out.println("发送重新检测命令到队列: " + queueName);
//                    System.out.println("检测命令内容: " + JSON.toJSONString(detectData));
                    rabbitMQService.sendMessage("", queueName, JSON.toJSONString(detectData));

                    channel.basicAck(deliveryTag, false);
                    return;
                }
            }

            // 处理基线检测结果（包括普通检测和重新检测的结果）
            boolean hasBaselineData = false;
            for (int i = 0; i < dataList.size(); i++) {
                JSONObject dataItem = dataList.getJSONObject(i);
                if ("baseline".equalsIgnoreCase(dataItem.getString("type"))) {
                    hasBaselineData = true;
                    JSONObject baselineData = dataItem.getJSONObject("data");

                    // 调用BaselineService处理数据
                    Map<String, Object> data = new HashMap<>();
                    data.put("macAddress", macAddress);
                    data.put("baselineData", baselineData);
                    baselineService.processBaselineData(data);
                }
            }

            // 只有在收到基线数据时才更新扫描记录
            if (hasBaselineData) {
                // 查找是否存在该MAC地址的最新记录
                BaselineScan existingScan = baselineScanMapper.selectLatestByMacAddress(macAddress);
                if (existingScan != null) {
                    // 存在记录，更新时间
                    existingScan.setStartTime(new Date());
                    baselineScanMapper.updateByPrimaryKey(existingScan);
//                    System.out.println("更新基线扫描记录时间，ID: " + existingScan.getId() + ", MAC: " + macAddress);
                } else {
                    // 不存在记录，创建新记录
                    BaselineScan baselineScan = new BaselineScan();
                    baselineScan.setMacAddress(macAddress);
                    baselineScan.setHostName(hostName);
                    baselineScan.setStartTime(new Date());
                    baselineScanMapper.insertSelective(baselineScan);
                    System.out.println("创建新的基线扫描记录，MAC: " + macAddress);
                }
            }

            System.out.println("基线检测结果处理成功，主机: " + macAddress);
            channel.basicAck(deliveryTag, false);
        } catch (Exception e) {
            System.err.println("处理基线检测结果失败: " + e.getMessage());
            e.printStackTrace();
            channel.basicAck(deliveryTag, false); // 避免消息重入队列
        }

    }
}
