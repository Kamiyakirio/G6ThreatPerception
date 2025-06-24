package com.tpp.threat_perception_platform.service.impl;

import com.tpp.threat_perception_platform.dao.HostMapper;
import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.pojo.Host;
import com.tpp.threat_perception_platform.service.HostService;
import com.tpp.threat_perception_platform.service.ScheduledMessageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@EnableScheduling
public class ScheduledMessageServiceImpl implements ScheduledMessageService {

    @Autowired
    private HostMapper hostMapper;
    @Autowired
    private HostService hostService;

    @Override
    @Scheduled(fixedRate = 1000)
    public void runEverySecondFixedRate() {
        MyParam myParam = new MyParam();
        myParam.setLimit(100000);
        myParam.setPage(1);
        List<Host> hosts=hostMapper.findAll(myParam);
        for(Host host:hosts){
            Integer isAlive=hostService.isHostAlive(host.getId());

        }
    }
}
