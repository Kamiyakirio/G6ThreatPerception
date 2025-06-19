package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.pojo.VulScan;

import java.util.List;

/**
* @author cindy
* @description 针对表【vul_scan】的数据库操作Mapper
* @createDate 2025-06-13 14:32:48
* @Entity com.tpp.threat_perception_platform.pojo.VulScan
*/
public interface VulScanMapper {

    int deleteByPrimaryKey(Long id);

    int insert(VulScan record);

    int insertSelective(VulScan record);

    VulScan selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(VulScan record);

    int updateByPrimaryKey(VulScan record);

    List<VulScan> selectAllByMacAddress(String macAddress);

    VulScan selectByMacAddressAndVulId(String macAddress, Long vulId);

    /**
     * 获取漏洞检测总数（按ID去重）
     * @return 漏洞检测总数
     */
    int countDistinctVulIds();

}
