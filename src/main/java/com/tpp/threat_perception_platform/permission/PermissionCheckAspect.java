package com.tpp.threat_perception_platform.permission;

import com.alibaba.fastjson.JSON;
import com.tpp.threat_perception_platform.response.ResponseResult;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Aspect
@Component
public class PermissionCheckAspect {

    @Autowired
    private JdbcTemplate jdbcTemplate;

//    @Before("@annotation(RequiresPermission)")
//    public void checkPermission(JoinPoint joinPoint) throws Throwable {
//        // 获取方法签名
//        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
//        Method method = signature.getMethod();
//
//        // 获取注解中的权限值
//        RequiresPermission annotation = method.getAnnotation(RequiresPermission.class);
//        String requiredPermission = annotation.value();
//
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//
//        String userName = authentication.getName();
//        Integer roleIdOfUser=jdbcTemplate.queryForObject("SELECT user_role FROM user where user_name=?",Integer.class,userName);
//        String roleNameOfUser=jdbcTemplate.queryForObject("SELECT role_name FROM role where role_id=?",String.class,roleIdOfUser);
//
//        List<String> userPermission=getPermissions(userName,"user");
//        List<String> rolePermission=getPermissions(roleNameOfUser,"role");
//
//        if (!(userPermission.contains(requiredPermission) || rolePermission.contains(requiredPermission))) {
//            throw new SecurityException("无访问权限：" + requiredPermission);
//        }
//
//    }
//
//    @Around("@annotation(requiresPermission)")
//    public Object around(ProceedingJoinPoint joinPoint, RequiresPermission requiresPermission) throws Throwable {
//        String requiredPermission = requiresPermission.value();
//        try {
//            checkPermission(requiredPermission);
//            // 有权限 → 放行执行原方法
//            return joinPoint.proceed();
//        } catch (SecurityException e) {
//            // 无权限 → 返回错误 JSON（与 ResponseResult 结构一致）
//            return new ResponseResult<>(1001, "您无权访问该接口！");
//        }
//    }

    public void checkPermission(String requiredPermission) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new SecurityException("用户未登录");
        }

        String userName = authentication.getName();
        Integer roleId = jdbcTemplate.queryForObject(
                "SELECT user_role FROM user WHERE user_name=?", Integer.class, userName);
        String roleName = jdbcTemplate.queryForObject(
                "SELECT role_name FROM role WHERE role_id=?", String.class, roleId);

        List<String> userPermissions = getPermissions(userName, "user");
        List<String> rolePermissions = getPermissions(roleName, "role");

        if (!(hasMatchedPermission(userPermissions, requiredPermission) || hasMatchedPermission(rolePermissions, requiredPermission))) {
            throw new SecurityException("无访问权限：" + requiredPermission);
        }
    }

    public List<String> getPermissions(String name, String type) {
        try {
            String sql = "SELECT value FROM permission WHERE name = ? AND type = ?";
            String encodedJson = jdbcTemplate.queryForObject(sql, String.class, name, type);
            if (encodedJson == null || encodedJson.trim().isEmpty()) {
                throw new RuntimeException("数据库中未找到权限信息");
            }

            // Base64 解码
            byte[] decodedBytes = Base64.getDecoder().decode(encodedJson);
            String json = new String(decodedBytes);

            // FastJSON 反序列化
            List<String> permissions = JSON.parseArray(json, String.class);

            return permissions;
        } catch (Exception e) {
            return new ArrayList<String>();
        }
    }

    private boolean hasMatchedPermission(List<String> permissions, String requiredPermission) {
        for (String perm : permissions) {
            if ("*".equals(perm)) {
                return true;
            }
            // 将权限表达式转换为正则
            String regex = Arrays.stream(perm.split("\\."))
                    .map(part -> "\\*".equals(part) ? "[^.]+?" : Pattern.quote(part))
                    .collect(Collectors.joining("\\."));

            if (requiredPermission.matches(regex)) {
                return true;
            }
        }
        return false;
    }

}