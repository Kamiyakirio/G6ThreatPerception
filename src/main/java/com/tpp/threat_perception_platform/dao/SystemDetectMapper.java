package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.Host;
import com.tpp.threat_perception_platform.pojo.SystemDetect;
import com.tpp.threat_perception_platform.param.SystemDetectParam;
import io.lettuce.core.dynamic.annotation.Param;

import java.util.List;
import java.util.Map;

/**
* @author 秦新奇
* @description 针对表【system_detect】的数据库操作Mapper
* @createDate 2025-06-13 10:07:34
* @Entity com.tpp.threat_perception_platform.pojo.SystemDetect
*/
public interface SystemDetectMapper {

    int deleteByPrimaryKey(Long id);


    int insertSelective(SystemDetect record);

    SystemDetect selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(SystemDetect record);

    int updateByPrimaryKey(SystemDetect record);

    List<Map<String, Object>> findDetectedHosts();

    //List<Map<String, Object>> findSystemDetectWithHostInfoByMac(@SystemDetectParam("macAddress") String macAddress);

    List<Map<String, Object>> findSystemDetectByMac(@Param("macAddress") String macAddress);


    Host selectByMacAddress(String macAddress);

    Integer countByMacAddress(String macAddress);

    void insert(SystemDetect systemDetect);

    List<Map<String, Object>> getDetectedHostsWithMaxRisk();
}
