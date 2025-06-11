package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.asset.Service;

import java.util.List;

/**
* @author 86157
* @description 针对表【service】的数据库操作Mapper
* @createDate 2025-06-11 11:26:40
* @Entity com.tpp.threat_perception_platform.asset.Service
*/
public interface ServiceMapper {

    int deleteByPrimaryKey(Long id);

    int insert(Service record);

    int insertSelective(Service record);

    Service selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(Service record);

    int updateByPrimaryKey(Service record);

    List<Service> selectAllByMacAddress(String macAddress);

    Integer selectLastDetectIdByMac(String macAddress);

    Service selectByNameAndHost(String name, String hostName);
}
