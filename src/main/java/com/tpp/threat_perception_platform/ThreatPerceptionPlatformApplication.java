package com.tpp.threat_perception_platform;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.amqp.rabbit.annotation.EnableRabbit;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableRabbit
@MapperScan("com.tpp.threat_perception_platform.dao")
public class ThreatPerceptionPlatformApplication {

    public static void main(String[] args) {
        SpringApplication.run(ThreatPerceptionPlatformApplication.class, args);
    }

}
