package com.tpp.threat_perception_platform.service;

import java.util.HashMap;

public interface PwdService {

    public HashMap<String,Object> pwdDetect(HashMap<String,Object> data);

    /**
     * 获取账户总数
     * @return 账户总数
     */
    public int getWeakPasswordCount();

}
