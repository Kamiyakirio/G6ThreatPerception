package com.tpp.threat_perception_platform.service;

import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.pojo.Role;
import com.tpp.threat_perception_platform.pojo.User;
import com.tpp.threat_perception_platform.response.ResponseResult;

public interface RoleService {

    public ResponseResult roleList(MyParam param);
    public ResponseResult delete(Integer[] ids);
    public ResponseResult edit(Role role);
}
