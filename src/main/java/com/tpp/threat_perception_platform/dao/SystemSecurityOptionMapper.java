package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.SystemSecurityOption;

import java.util.List;

/**
* @author Zyzjr
* @description 针对表【system_security_option】的数据库操作Mapper
* @createDate 2025-06-23 13:15:01
* @Entity com.tpp.threat_perception_platform.pojo.SystemSecurityOption
*/
public interface SystemSecurityOptionMapper {

    int deleteByPrimaryKey(Long id);

    int insert(SystemSecurityOption record);

    int insertSelective(SystemSecurityOption record);

    SystemSecurityOption selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(SystemSecurityOption record);

    int updateByPrimaryKey(SystemSecurityOption record);

    // 新增：按type查询全部
    List<SystemSecurityOption> selectByType(String type);
    // 新增：按type和mac_address查询
    List<SystemSecurityOption> selectByTypeAndMac(String type, String macAddress);

}
