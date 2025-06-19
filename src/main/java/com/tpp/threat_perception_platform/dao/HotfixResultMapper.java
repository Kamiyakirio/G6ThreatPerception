package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.HotfixResult;
import org.apache.ibatis.annotations.MapKey;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Map;

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

    /**
     * 分页查询补丁检测结果
     * @param hostId 主机ID
     * @param offset 偏移量
     * @param limit 每页数量
     * @return 补丁检测结果列表
     */
    List<HotfixResult> selectPageList(@Param("hostId") String hostId, 
                                    @Param("offset") Integer offset, 
                                    @Param("limit") Integer limit);

    /**
     * 获取总记录数
     * @param hostId 主机ID
     * @return 总记录数
     */
    int selectTotalCount(@Param("hostId") String hostId);

    /**
     * 按补丁号分组查询结果
     */
    @MapKey("kb_id")
    List<Map<String, Object>> selectGroupByKbId(@Param("hostId") String hostId, 
                                               @Param("offset") Integer offset, 
                                               @Param("limit") Integer limit);

    /**
     * 获取分组后的总记录数
     */
    int selectGroupTotalCount(@Param("hostId") String hostId);

    /**
     * 获取补丁检测总数（按KB ID去重）
     * @return 补丁检测总数
     */
    int countDistinctKbIds();
}
