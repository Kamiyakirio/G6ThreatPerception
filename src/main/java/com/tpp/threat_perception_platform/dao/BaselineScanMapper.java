package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.BaselineScan;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

/**
* @author Zyzjr
* @description 针对表【baseline_scan】的数据库操作Mapper
* @createDate 2025-06-23 14:01:36
* @Entity com.tpp.threat_perception_platform.pojo.BaselineScan
*/
@Mapper
public interface BaselineScanMapper {

    int deleteByPrimaryKey(Long id);

    int insert(BaselineScan record);

    int insertSelective(BaselineScan record);

    BaselineScan selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(BaselineScan record);

    int updateByPrimaryKey(BaselineScan record);

    // 根据MAC地址查询
    List<BaselineScan> selectByMacAddress(String macAddress);

    // 根据MAC地址获取最新记录
    @Select("SELECT * FROM baseline_scan WHERE mac_address = #{macAddress} ORDER BY id DESC LIMIT 1")
    BaselineScan selectLatestByMacAddress(@Param("macAddress") String macAddress);

    // 分页查询
    List<BaselineScan> selectPageList(@Param("macAddress") String macAddress,
                                    @Param("taskTime") String taskTime,
                                    @Param("offset") Integer offset,
                                    @Param("limit") Integer limit);

    // 查询总数
    Integer selectTotalCount(@Param("macAddress") String macAddress,
                           @Param("taskTime") String taskTime);

  }
