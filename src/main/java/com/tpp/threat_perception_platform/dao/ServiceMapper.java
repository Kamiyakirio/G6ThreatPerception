package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.asset.Service;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
* @author 86157
* @description 针对表【service】的数据库操作Mapper
* @createDate 2025-06-11 09:42:50
* @Entity com.tpp.threat_perception_platform.asset.Service
*/
public interface ServiceMapper {

    int deleteByPrimaryKey(Long id);

    int insert(Service record);

    int insertSelective(Service record);

    Service selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(Service record);

    int updateByPrimaryKey(Service record);

    List<Service> selectByHostNameAndMacAddress(@Param("hostName") String hostName, @Param("macAddress") String macAddress);

    Service selectByNameAndHost(String name, String hostName);
}
