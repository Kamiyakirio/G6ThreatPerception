package com.tpp.threat_perception_platform.service;

import org.springframework.scheduling.annotation.Scheduled;

public interface ScheduledMessageService {

    void runEverySecondFixedRate();
}
