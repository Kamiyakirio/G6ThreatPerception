package com.tpp.threat_perception_platform.websocket;

import com.alibaba.fastjson.JSON;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.*;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.util.Map;
import java.util.concurrent.CopyOnWriteArraySet;

@Component
public class StatusWebSocketHandler extends TextWebSocketHandler {

    // 保存所有连接的客户端
    private static final CopyOnWriteArraySet<WebSocketSession> sessions = new CopyOnWriteArraySet<>();

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        sessions.add(session);
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        sessions.remove(session);
    }

    // 自定义方法：当状态改变时调用，群发消息
    public void broadcastStatusChange(String message) {
        for (WebSocketSession session : sessions) {
            try {
                session.sendMessage(new TextMessage(message));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void broadcastMessage(String message, Integer iconType) {
        broadcastStatusChange(JSON.toJSONString(Map.of("message",message,"iconType",iconType,"type","message")));
    }
}
