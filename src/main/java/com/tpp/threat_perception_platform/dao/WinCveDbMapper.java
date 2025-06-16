package com.tpp.threat_perception_platform.dao;


import com.tpp.threat_perception_platform.pojo.WinCveDb;

/**
* @author 13626
* @description 针对表【win_cve_db(Windows漏洞与KB补丁关系库)】的数据库操作Mapper
* @createDate 2025-06-13 09:50:19
* @Entity com.tpp.threat_perception_platform.pojo.WinCveDb
*/
public interface WinCveDbMapper {

    int deleteByPrimaryKey(Long id);

    int insert(WinCveDb record);

    int insertSelective(WinCveDb record);

    WinCveDb selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(WinCveDb record);

    int updateByPrimaryKey(WinCveDb record);

}
