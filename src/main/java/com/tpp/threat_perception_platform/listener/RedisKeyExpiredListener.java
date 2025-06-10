package com.tpp.threat_perception_platform.listener;

import com.tpp.threat_perception_platform.dao.HostMapper;
import com.tpp.threat_perception_platform.pojo.Host;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.listener.KeyExpirationEventMessageListener;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.stereotype.Component;

@Component
public class RedisKeyExpiredListener extends KeyExpirationEventMessageListener {

    @Autowired
    private HostMapper hostMapper;

    public RedisKeyExpiredListener(RedisMessageListenerContainer listenerContainer) {
        super(listenerContainer);
    }

    @Override
    public void onMessage(Message message, byte[] pattern) {
        String expiredKey = message.toString();
        // 你可以在这里处理 key 过期事件，例如：client:heartbeat:xxx 代表某个客户端下线了
        System.out.println("Key expired: " + expiredKey);
        if(expiredKey.startsWith("Heartbeat from ")) {
            String macAddress = expiredKey.replace("Heartbeat from ", "");
            Host host = hostMapper.selectByMacAddress(macAddress);
            host.setIsAlive(0);
            hostMapper.updateByPrimaryKey(host);
            System.out.println(macAddress + " lost heartbeat!");
        }
    }
}
