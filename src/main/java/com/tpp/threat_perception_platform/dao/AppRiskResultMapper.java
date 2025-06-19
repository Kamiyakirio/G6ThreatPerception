package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.AppRiskResult;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface AppRiskResultMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(AppRiskResult record);

    int insertSelective(AppRiskResult record);

    AppRiskResult selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(AppRiskResult record);

    int updateByPrimaryKey(AppRiskResult record);

    // 根据hostIdentifier查询结果
    List<AppRiskResult> selectByHostIdentifier(@Param("hostIdentifier") String hostIdentifier);

    // 根据macAddress查询结果
    List<AppRiskResult> selectByMacAddress(@Param("macAddress") String macAddress);

    // 查询最新的detect_id
    Integer selectLastDetectIdByHostIdentifier(@Param("hostIdentifier") String hostIdentifier);

    // 获取最新一次检测的结果
    List<AppRiskResult> selectLatestByMacAddress(@Param("macAddress") String macAddress);

    // 获取所有应用风险结果的总数
    int selectTotalCount();
} 