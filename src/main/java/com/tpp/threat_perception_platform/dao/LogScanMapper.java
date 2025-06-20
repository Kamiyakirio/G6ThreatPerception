package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.LogScan;

/**
* @author cindy
* @description 针对表【log_scan】的数据库操作Mapper
* @createDate 2025-06-20 11:27:05
* @Entity com.tpp.threat_perception_platform.pojo.LogScan
*/
public interface LogScanMapper {

    int deleteByPrimaryKey(Long id);

    int insert(LogScan record);

    int insertSelective(LogScan record);

    LogScan selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(LogScan record);

    int updateByPrimaryKey(LogScan record);

}
