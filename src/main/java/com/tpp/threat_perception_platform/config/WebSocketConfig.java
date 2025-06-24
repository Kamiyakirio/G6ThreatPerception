package com.tpp.threat_perception_platform.config;

import com.tpp.threat_perception_platform.websocket.StatusWebSocketHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.*;

@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    @Autowired
    private StatusWebSocketHandler statusWebSocketHandler;

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(statusWebSocketHandler, "/ws/status")
                .setAllowedOrigins("*"); // 允许所有前端连接
    }
}