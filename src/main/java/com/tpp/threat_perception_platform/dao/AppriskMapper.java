package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.Apprisk;

/**
* @author Zyzjr
* @description 针对表【apprisk】的数据库操作Mapper
* @createDate 2025-06-12 16:02:22
* @Entity com.tpp.threat_perception_platform.pojo.Apprisk
*/
public interface AppriskMapper {

    int deleteByPrimaryKey(Long id);

    int insert(Apprisk record);

    int insertSelective(Apprisk record);

    Apprisk selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(Apprisk record);

    int updateByPrimaryKey(Apprisk record);

}
