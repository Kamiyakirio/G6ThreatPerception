package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.SystemAccess;
import java.util.List;

/**
* @author Zyzjr
* @description 针对表【system_access】的数据库操作Mapper
* @createDate 2025-06-23 13:14:32
* @Entity com.tpp.threat_perception_platform.pojo.SystemAccess
*/
public interface SystemAccessMapper {

    int deleteByPrimaryKey(Long id);

    int insert(SystemAccess record);

    int insertSelective(SystemAccess record);

    SystemAccess selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(SystemAccess record);

    int updateByPrimaryKey(SystemAccess record);

    List<SystemAccess> selectByType(String type);

    List<SystemAccess> selectByTypeAndMac(String type, String macAddress);

}
