package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.asset.Account;

/**
* @author 86157
* @description 针对表【account】的数据库操作Mapper
* @createDate 2025-06-10 19:12:29
* @Entity com.tpp.threat_perception_platform.asset.Account
*/
public interface AccountMapper {

    int deleteByPrimaryKey(Long id);

    int insert(Account record);

    int insertSelective(Account record);

    Account selectByPrimaryKey(String sid);

    int updateByPrimaryKeySelective(Account record);

    int updateByPrimaryKey(Account record);

}
