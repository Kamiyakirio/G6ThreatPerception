package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.asset.App;

import java.util.List;

/**
* @author 86157
* @description 针对表【app】的数据库操作Mapper
* @createDate 2025-06-11 11:26:04
* @Entity com.tpp.threat_perception_platform.asset.App
*/
public interface AppMapper {

    int deleteByPrimaryKey(Long id);

    int insert(App record);

    int insertSelective(App record);

    App selectByPrimaryKey(Long id);

    Integer selectLastDetectIdByMac(String macAddress);

    List<App> selectAllByMacAddress(String macAddress);

    int updateByPrimaryKeySelective(App record);

    int updateByPrimaryKey(App record);

}
