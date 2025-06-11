package com.tpp.threat_perception_platform.dao;

import com.tpp.threat_perception_platform.asset.Account;

import java.util.List;

/**
* @author 86157
* @description 针对表【account】的数据库操作Mapper
* @createDate 2025-06-11 11:25:29
* @Entity com.tpp.threat_perception_platform.asset.Account
*/
public interface AccountMapper {

    int deleteByPrimaryKey(Long id);

    int insert(Account record);

    int insertSelective(Account record);

    Account selectByPrimaryKey(String id);

    int updateByPrimaryKeySelective(Account record);

    Integer selectLastDetectIdByMac(String macAddress);

    int updateByPrimaryKey(Account record);

    List<Account> selectAllByMacAddress(String macAddress);

}
