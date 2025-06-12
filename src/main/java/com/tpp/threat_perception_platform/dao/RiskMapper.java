package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.Risk;

import java.util.List;

/**
* @author cindy
* @description 针对表【risk】的数据库操作Mapper
* @createDate 2025-06-12 09:12:29
* @Entity com.tpp.threat_perception_platform.pojo.Risk
*/
public interface RiskMapper {

    int deleteByPrimaryKey(Long id);

    int insert(Risk record);

    int insertSelective(Risk record);

    Risk selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(Risk record);

    int updateByPrimaryKey(Risk record);

    List<Risk> selectAllByType(String Type);

}
