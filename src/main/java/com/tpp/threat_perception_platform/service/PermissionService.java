package com.tpp.threat_perception_platform.service;

public interface PermissionService {
    public String getUserPermissions(String name);
    public String getRolePermissions(String name);
    public Integer savePermissions(String name,String type,String value);
}
