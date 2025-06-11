package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.asset.Process;

/**
* @author 86157
* @description 针对表【process】的数据库操作Mapper
* @createDate 2025-06-10 20:46:56
* @Entity com.tpp.threat_perception_platform.asset.Process
*/
public interface ProcessMapper {

    int deleteByPrimaryKey(Long id);

    int insert(Process record);

    int insertSelective(Process record);

    Process selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(Process record);

    int updateByPrimaryKey(Process record);

    Process selectByPidAndHost(Integer pid, String hostName);

}
