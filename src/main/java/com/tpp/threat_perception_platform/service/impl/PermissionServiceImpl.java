package com.tpp.threat_perception_platform.service.impl;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.databind.ser.Serializers;
import com.tpp.threat_perception_platform.service.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Map;

@Service
public class PermissionServiceImpl implements PermissionService {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public String getUserPermissions(String name) {
        try {
            Integer roleId = jdbcTemplate.queryForObject(
                    "SELECT user_role FROM user WHERE user_name=?", Integer.class, name);
            String roleName = jdbcTemplate.queryForObject(
                    "SELECT role_name FROM role WHERE role_id=?", String.class, roleId);
            String encodedUserJson = jdbcTemplate.queryForObject("SELECT value FROM permission WHERE name=? and type='user'", String.class, name);
            String encodedRoleJson = jdbcTemplate.queryForObject("SELECT value FROM permission WHERE name=? and type='role'", String.class, roleName);
            // Base64 解码
            byte[] decodedBytes = Base64.getDecoder().decode(encodedUserJson);
            byte[] decodedBytes1 = Base64.getDecoder().decode(encodedRoleJson);

            return new String(JSON.toJSONString(Map.of("userPermission", new String(decodedBytes), "rolePermission", new String(decodedBytes1))));
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public String getRolePermissions(String name) {
        try {
            String encodedRoleJson = jdbcTemplate.queryForObject("SELECT value FROM permission WHERE name=? and type='role'", String.class, name);
            // Base64 解码
            byte[] decodedBytes = Base64.getDecoder().decode(encodedRoleJson);

            return new String(JSON.toJSONString(Map.of("rolePermission", new String(decodedBytes))));
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public Integer savePermissions(String name, String type, String value) {
        String sql="UPDATE permission SET value=? WHERE name=? and type=?";
        value= Base64.getEncoder().encodeToString(value.getBytes());
        return jdbcTemplate.update(sql,value,name,type);
    }
}
