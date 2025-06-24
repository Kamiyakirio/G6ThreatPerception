package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.BaselineTask;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface BaselineTaskMapper {
    List<BaselineTask> findAll();
    BaselineTask selectById(@Param("id") Integer id);
    int insert(BaselineTask task);
    int update(BaselineTask task);
    int deleteById(@Param("id") Integer id);
} 