package com.tpp.threat_perception_platform.dao;

import org.apache.ibatis.annotations.Param;
import java.util.List;
import java.util.Map;

public interface HotfixMapper {
    List<Map<String, Object>> findHotfixList(@Param("hostId") Integer hostId);
} 