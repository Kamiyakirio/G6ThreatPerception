package com.tpp.threat_perception_platform.permission;

import com.alibaba.fastjson.JSON;
import com.tpp.threat_perception_platform.response.ResponseResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.method.HandlerMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;


@Component
public class PermissionInterceptor implements HandlerInterceptor {
    @Autowired
    private PermissionCheckAspect permissionCheckAspect;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        // 非控制器方法，直接放行
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }
        HandlerMethod handlerMethod = (HandlerMethod) handler;

        // 获取方法上的注解
        RequiresPermission annotation = handlerMethod.getMethodAnnotation(RequiresPermission.class);
        if (annotation == null) {
            return true; // 没加注解的接口直接放行
        }

        String permissionCode = annotation.value();

        try {
            // 用你的统一权限检查逻辑判断（来自 PermissionCheckAspect）
            permissionCheckAspect.checkPermission(permissionCode);
            return true; // ✅ 有权限，放行
        } catch (SecurityException e) {
            // ❌ 无权限，返回 JSON，阻止方法执行
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");

            ResponseResult result = new ResponseResult<>(1001, "无访问权限：" + permissionCode);
            response.getWriter().write(JSON.toJSONString(result));
            return false;
        }
    }
}
