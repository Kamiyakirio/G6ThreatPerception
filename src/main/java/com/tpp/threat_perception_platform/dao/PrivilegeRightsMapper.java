package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.PrivilegeRights;

import java.util.List;

/**
* @author Zyzjr
* @description 针对表【privilege_rights】的数据库操作Mapper
* @createDate 2025-06-23 13:13:45
* @Entity com.tpp.threat_perception_platform.pojo.PrivilegeRights
*/
public interface PrivilegeRightsMapper {

    int deleteByPrimaryKey(Long id);

    int insert(PrivilegeRights record);

    int insertSelective(PrivilegeRights record);

    PrivilegeRights selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(PrivilegeRights record);

    int updateByPrimaryKey(PrivilegeRights record);

    // 新增：按type查询全部
    List<PrivilegeRights> selectByType(String type);
    // 新增：按type和mac_address查询
    List<PrivilegeRights> selectByTypeAndMac(String type, String macAddress);

}
