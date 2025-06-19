package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.Log;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
* @author Zyzjr
* @description 针对表【log】的数据库操作Mapper
* @createDate 2025-06-17 19:57:23
* @Entity com.tpp.threat_perception_platform.pojo.Log
*/
public interface LogMapper {

    int deleteByPrimaryKey(Long id);

    int insert(Log record);

    int insertSelective(Log record);

    Log selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(Log record);

    int updateByPrimaryKey(Log record);

    /**
     * 根据macAddress、eventId、timestamp和channel查询是否存在相同的日志记录
     */
    Log selectByMacAddressAndEventIdAndTimestampAndChannel(String macAddress, Integer eventId, Date timestamp, String channel);

    /**
     * 根据MAC地址查询日志记录
     */
    List<Log> selectByMacAddress(String macAddress);

    /**
     * 获取登录日志总数
     */
    Long selectTotalLogs();

    /**
     * 获取风险日志总数
     */
    Long selectTotalRiskLogs();

    /**
     * 获取风险等级分布统计
     */
    List<Map<String, Object>> selectRiskDistribution();

    /**
     * 分页查询日志列表
     */
    List<Log> selectLogList(Map<String, Object> params);

    /**
     * 获取日志总数（用于分页）
     */
    Long selectLogCount(Map<String, Object> params);

    Long countByEventIds(@org.apache.ibatis.annotations.Param("eventIds") java.util.List<Integer> eventIds, @org.apache.ibatis.annotations.Param("riskLevelMin") Integer riskLevelMin);

    List<Map<String, Object>> selectRiskDistributionByEventIds(@org.apache.ibatis.annotations.Param("eventIds") java.util.List<Integer> eventIds);

    Long countSystemLogs();
    Long countSecurityLogs();
}
