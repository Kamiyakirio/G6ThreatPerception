package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.asset.App;

/**
* @author 86157
* @description 针对表【app】的数据库操作Mapper
* @createDate 2025-06-10 20:11:27
* @Entity com.tpp.threat_perception_platform.asset.App
*/
public interface AppMapper {

    int deleteByPrimaryKey(Integer  app_id);

    int insert(App record);

    int insertSelective(App record);

    App selectByPrimaryKey(Integer  app_id);

    int updateByPrimaryKeySelective(App record);

    int updateByPrimaryKey(App record);

}
