package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.HotfixResult;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
* @author 13626
* @description 针对表【hotfix_result(主机补丁扫描结果表)】的数据库操作Mapper
* @createDate 2025-06-13 13:13:16
* @Entity com.tpp.threat_perception_platform.pojo.HotfixResult
*/
public interface HotfixResultMapper {

    int deleteByPrimaryKey(Long id);

    int insert(HotfixResult record);

    int insertSelective(HotfixResult record);

    HotfixResult selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(HotfixResult record);

    int updateByPrimaryKey(HotfixResult record);

    /**
     * 批量插入补丁检测结果
     * @param macAddress 主机MAC地址
     * @param kbIds 补丁ID列表
     * @return 插入的记录数
     */
    int batchInsertHotfixResults(@Param("macAddress") String macAddress, @Param("kbIds") List<String> kbIds);

}
