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
import com.tpp.threat_perception_platform.pojo.AppRiskResult;
import com.tpp.threat_perception_platform.pojo.Host;
import com.tpp.threat_perception_platform.pojo.Risk;
import com.tpp.threat_perception_platform.pojo.VulScan;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Objects;

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
            System.out.println("收到主机信息消息: " + messageBody);

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
            System.out.println("处理主机信息失败: " + e.getMessage());
            e.printStackTrace();
            channel.basicNack(tag, false, true);
        }
    }

    @RabbitListener(queues = "detect_result")
    public void receiveDetectResult(String messageBody, Message message, Channel channel) throws IOException {
        long deliveryTag = message.getMessageProperties().getDeliveryTag();

        try {
            JSONObject fullData = JSON.parseObject(messageBody);
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

                        Account dbAccount = accountMapper.selectByPrimaryKey(account.getId());
                        if (dbAccount == null) {
                            accountMapper.insertSelective(account);
                        } else if (!dbAccount.equals(account)) {
                            accountMapper.updateByPrimaryKeySelective(account);
                        }
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

                        Process dbProcess = processMapper.selectByPidAndHost(process.getPid(), process.getHostName());
                        if (dbProcess == null) {
                            processMapper.insertSelective(process);
                        } else if (!dbProcess.equals(process)) {
                            process.setProcessId(dbProcess.getProcessId());
                            processMapper.updateByPrimaryKeySelective(process);
                        }
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

                        Service dbService = serviceMapper.selectByNameAndHost(service.getName(), service.getHostName());
                        if (dbService == null) {
                            serviceMapper.insertSelective(service);
                        } else if (!dbService.equals(service)) {
                            service.setServiceId(dbService.getServiceId());
                            serviceMapper.updateByPrimaryKeySelective(service);
                        }
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
        System.out.println("收到应用风险探测结果: " + messageBody);

        try {
            JSONObject jsonObject = JSON.parseObject(messageBody);
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
                System.out.println("应用风险探测结果已保存到数据库");
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
        System.out.println("接收到密码检测结果：" + messageBody);
        long deliveryTag = message.getMessageProperties().getDeliveryTag();

        try {
            JSONObject fullData = JSON.parseObject(messageBody);
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
            JSONObject fullData = JSON.parseObject(messageBody);
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
}
