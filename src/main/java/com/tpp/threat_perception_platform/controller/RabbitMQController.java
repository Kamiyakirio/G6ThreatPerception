package com.tpp.threat_perception_platform.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.tpp.threat_perception_platform.asset.Account;
import com.tpp.threat_perception_platform.asset.App;
import com.tpp.threat_perception_platform.asset.Service;
import com.tpp.threat_perception_platform.dao.*;
import com.tpp.threat_perception_platform.pojo.AppRiskResult;
import com.tpp.threat_perception_platform.pojo.Host;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.amqp.RabbitProperties;
import org.springframework.stereotype.Component;
import com.alibaba.fastjson.JSONObject;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import com.tpp.threat_perception_platform.asset.Process;

@Component
public class RabbitMQController {

    @Autowired
    private HostMapper hostMapper;
    @Autowired
    private AccountMapper  accountMapper;
    @Autowired
    private AppMapper appMapper;
    @Autowired
    private ProcessMapper  processMapper;
    @Autowired
    private ServiceMapper serviceMapper;
    @Autowired
    private AppRiskResultMapper appRiskResultMapper;


    //查询并设置探测结构id
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
    public void receiveHostInfo(String messageBody, Message message, Channel channel) throws IOException {
        long tag = message.getMessageProperties().getDeliveryTag();
//        System.out.println(messageBody);

        Host host = new Host();
        HashMap<String, Object> dataDict = JSON.parseObject(messageBody, HashMap.class);

        host.setMacAddress(dataDict.get("macAddress").toString());
        host.setHostName(dataDict.get("pcName").toString());
        host.setIpAddress(dataDict.get("ipAddress").toString());
        host.setOsType(dataDict.get("osName").toString());
        host.setOsName(dataDict.get("osName").toString() + " "+dataDict.get("osNameDetailed").toString());
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

                    int detectId = getNextDetectId(macAddress, accountMapper); // 获取 detect_id
                    for (int j = 0; j < accountsArray.size(); j++) {
                        JSONObject accountData = accountsArray.getJSONObject(j);
                        Account dbAccount = accountMapper.selectByPrimaryKey(accountData.getString("sid"));

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

                        Boolean disabled = accountData.getBoolean("disabled");
                        account.setDisabled(disabled != null && disabled ? 1 : 0);

                        Boolean lockout = accountData.getBoolean("lockout");
                        account.setLockout(lockout != null && lockout ? 1 : 0);

                        Boolean passwordChangeable = accountData.getBoolean("password_changeable");
                        account.setPasswordChangeable(passwordChangeable != null && passwordChangeable ? 1 : 0);

                        Boolean passwordExpires = accountData.getBoolean("password_expires");
                        account.setPasswordExpires(passwordExpires != null && passwordExpires ? 1 : 0);

                        Boolean passwordRequired = accountData.getBoolean("password_required");
                        account.setPasswordRequired(passwordRequired != null && passwordRequired ? 1 : 0);

                        account.setTime(new Date());

                        if (dbAccount == null) {
                            accountMapper.insertSelective(account);
                        } else if (!dbAccount.equals(account)) {
                            accountMapper.updateByPrimaryKeySelective(account);
                        }
                    }
                }

                // 处理 type=app 的逻辑
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

                        // 创建 Process 对象并填充基础信息
                        Process process = new Process();

                        process.setDetectId(detectId);
                        process.setHostName(hostName);
                        process.setMacAddress(macAddress);
                        process.setTime(time);
                        process.setId(id);

                        // 设置进程字段
                        process.setPid(processData.getInteger("pid"));
                        process.setPpid(processData.getInteger("ppid"));
                        process.setName(processData.getString("name"));
                        process.setCmd(processData.getString("cmd"));
                        process.setPriority(processData.getInteger("priority"));
                        process.setDescription(processData.getString("description"));

                        // 查询是否已存在该进程（根据 pid + hostName 判断）
                        Process dbProcess = processMapper.selectByPidAndHost(process.getPid(), process.getHostName());

                        if (dbProcess == null) {
                            processMapper.insertSelective(process);
                        } else if (!dbProcess.equals(process)) {
                            process.setProcessId(dbProcess.getProcessId()); // 保留原有主键
                            processMapper.updateByPrimaryKeySelective(process);
                        }
                    }
                }
                if ("service".equalsIgnoreCase(dataType)){
                    JSONArray servicesArray = dataItem.getJSONArray("data");
                    int detectId = getNextDetectId(macAddress, serviceMapper);

                    for (int j = 0; j < servicesArray.size(); j++) {
                        JSONObject serviceData = servicesArray.getJSONObject(j);

                        // 创建 Service 对象并填充基础信息
                        Service service = new Service();

                        service.setDetectId(detectId);
                        service.setHostName(hostName);
                        service.setMacAddress(macAddress);
                        service.setTime(time);
                        service.setId(id);

                        // 设置服务字段
                        service.setProtocol(serviceData.getString("protocol"));
                        service.setPort(serviceData.getInteger("port"));
                        service.setState(serviceData.getString("state"));
                        service.setName(serviceData.getString("name"));
                        service.setProduct(serviceData.getString("product"));
                        service.setVersion(serviceData.getString("version"));
                        service.setExtrainfo(serviceData.getString("extrainfo"));

                        // 查询是否已存在该服务（根据 name + hostName 判断）
                        Service dbService = serviceMapper.selectByNameAndHost(service.getName(), service.getHostName());

                        if (dbService == null) {
                            serviceMapper.insertSelective(service);
                        } else if (!dbService.equals(service)) {
                            service.setServiceId(dbService.getServiceId()); // 保留原有主键
                            serviceMapper.updateByPrimaryKeySelective(service);
                        }
                    }
                }
            }

            channel.basicAck(deliveryTag, false);

        } catch (Exception e) {
            //失败后仍然确认消息
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
            
            // 获取MAC地址和主机标识符
            String macAddress = info.getString("macAddress");
            String hostIdentifier = info.getString("hostIdentifier");
            
            if (data != null && !data.isEmpty()) {
                for (int i = 0; i < data.size(); i++) {
                    JSONObject riskData = data.getJSONObject(i);
                    AppRiskResult result = new AppRiskResult();
                    
                    // 设置基本字段
                    result.setHostIdentifier(hostIdentifier);
                    result.setMacAddress(macAddress);
                    result.setAppriskId(riskData.getInteger("appriskId"));
                    result.setIsVulnerable(riskData.getByte("isVulnerable"));
                    result.setResultEvidence(riskData.getString("resultEvidence"));
                    result.setDetectedAt(new Date());
                    
                    // 插入数据库
                    appRiskResultMapper.insertSelective(result);
                }
                System.out.println("应用风险探测结果已保存到数据库");
            }
            
            // 确认消息已被处理
            channel.basicAck(deliveryTag, false);
            
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("处理应用风险探测结果失败: " + e.getMessage());
            
            // 如果处理失败，拒绝消息并重新入队
            channel.basicNack(deliveryTag, false, true);
        }
    }
}
