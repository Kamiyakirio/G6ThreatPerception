package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.asset.Process;

import java.util.List;

/**
* @author 86157
* @description 针对表【process】的数据库操作Mapper
* @createDate 2025-06-11 11:26:23
* @Entity com.tpp.threat_perception_platform.asset.Process
*/
public interface ProcessMapper {

    int deleteByPrimaryKey(Long id);

    int insert(Process record);

    int insertSelective(Process record);

    Process selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(Process record);

    int updateByPrimaryKey(Process record);

    Integer selectLastDetectIdByMac(String macAddress);

    List<Process> selectAllByMacAddress(String macAddress);


    Process selectByPidAndHost(Integer pid, String hostName);

    List<Process> selectAllByDetectId(Integer detectId);

    int selectTotalCount();
}
