package com.tpp.threat_perception_platform.service.impl;

import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.tpp.threat_perception_platform.dao.RoleMapper;
import com.tpp.threat_perception_platform.param.MyParam;
import com.tpp.threat_perception_platform.pojo.Role;
import com.tpp.threat_perception_platform.pojo.User;
import com.tpp.threat_perception_platform.response.ResponseResult;
import com.tpp.threat_perception_platform.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.List;

@Service
public class RoleServiceImpl implements RoleService {

    @Autowired
    private RoleMapper roleMapper;

    @Override
    public ResponseResult roleList(MyParam param) {
        // 设置分页参数geInfo<>(roleList);

        PageHelper.startPage(param.getPage(), param.getLimit());
        // 查询所有
        List<Role> roleList = roleMapper.findAll(param);
        // 构架pageInfo
        PageInfo<Role> pageInfo = new PageInfo(roleList);
        return new ResponseResult<>(pageInfo.getTotal(), pageInfo.getList());
    }

    @Override
    public ResponseResult delete(Integer[] ids) {
        for (Integer id : ids) {
            roleMapper.deleteByPrimaryKey((long)id);
        }
        return new ResponseResult<>(0, "删除成功！");
    }

    @Override
    public ResponseResult edit(Role role) {
        int result = roleMapper.updateByPrimaryKey(role);
        if(result > 0) return new ResponseResult<>(0, "修改成功！");
        else return new ResponseResult(1,"修改失败！");
    }


}
