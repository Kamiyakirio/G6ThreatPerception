package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.EventAudit;

import java.util.List;

/**
* @author Zyzjr
* @description 针对表【event_audit】的数据库操作Mapper
* @createDate 2025-06-23 13:13:23
* @Entity com.tpp.threat_perception_platform.pojo.EventAudit
*/
public interface EventAuditMapper {

    int deleteByPrimaryKey(Long id);

    int insert(EventAudit record);

    int insertSelective(EventAudit record);

    EventAudit selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(EventAudit record);

    int updateByPrimaryKey(EventAudit record);

    // 新增：按type查询全部
    List<EventAudit> selectByType(String type);
    // 新增：按type和mac_address查询
    List<EventAudit> selectByTypeAndMac(String type, String macAddress);

}
