package com.tpp.threat_perception_platform.service;

import com.tpp.threat_perception_platform.dao.HotfixResultMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class HotfixResultService {
    
    private static final Logger logger = LoggerFactory.getLogger(HotfixResultService.class);
    
    @Autowired
    private HotfixResultMapper hotfixResultMapper;

    /**
     * 处理补丁检测结果
     * @param results 补丁检测结果列表
     * @return 处理的记录数
     */
    @Transactional
    public int processHotfixResults(List<Map<String, String>> results) {
        if (results == null || results.isEmpty()) {
            logger.warn("收到空的补丁检测结果");
            return 0;
        }

        // 获取第一个结果的MAC地址（所有结果应该是同一个主机的）
        String macAddress = results.get(0).get("macAddress");
        
        // 提取所有的补丁ID
        List<String> kbIds = results.stream()
                .map(result -> result.get("hotfixId"))
                .collect(Collectors.toList());
                
        logger.info("准备处理补丁检测结果：");
        logger.info("MAC地址: {}", macAddress);
        logger.info("补丁列表: {}", kbIds);

        // 批量插入结果
        int count = hotfixResultMapper.batchInsertHotfixResults(macAddress, kbIds);
        logger.info("补丁检测结果处理完成，插入记录数: {}", count);
        
        return count;
    }
} 