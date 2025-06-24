package com.tpp.threat_perception_platform.permission;

import com.alibaba.fastjson.JSON;
import com.tpp.threat_perception_platform.service.PermissionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class PermissionController {

    @Autowired
    private PermissionCheckAspect permissionCheckAspect;

    @Autowired
    private PermissionService permissionService;


    @GetMapping("/check_permission/{path}")
    public ResponseEntity checkPermission(@PathVariable("path") String permission, HttpServletRequest request) {
        try{
            permissionCheckAspect.checkPermission(permission);
        } catch (SecurityException e){
            return ResponseEntity.status(403).body(e.getMessage());
        }
        return ResponseEntity.ok().build();
    }

    @RequiresPermission("permission.list")
    @PostMapping("/permissions/get")
    public ResponseEntity getPermissions(@RequestBody Map<String, String> body) {
        String name = body.get("name");
        String type = body.get("type");// 设置Content-Type为application/json
        if(!type.equals("user")&&!type.equals("role")){
            return ResponseEntity.status(403).contentType(MediaType.APPLICATION_JSON).body(Map.of("code",1001,"msg","请求错误！"));
        }
        if(type.equals("user")){
            String result= permissionService.getUserPermissions(name);
            if(result==null){
                return ResponseEntity.status(403).contentType(MediaType.APPLICATION_JSON).body(Map.of("code",1001,"msg","请求错误！"));
            }
            return ResponseEntity.ok().body(result);

        } else if(type.equals("role")){
            String result= permissionService.getRolePermissions(name);
            if(result==null){
                return ResponseEntity.status(403).contentType(MediaType.APPLICATION_JSON).body(Map.of("code",1001,"msg","请求错误！"));
            }
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result);
        }
        return ResponseEntity.status(403).contentType(MediaType.APPLICATION_JSON).body(Map.of("code",1001,"msg","请求错误！"));
    }

    @PostMapping("/permissions/save")
    public ResponseEntity savePermissions(@RequestBody Map<String, Object> body) {
        String name = body.get("name").toString();
        String type = body.get("type").toString();
        if(!type.equals("user")&&!type.equals("role")||null==name){
            return ResponseEntity.status(403).body(Map.of("code",1001,"msg","请求错误！"));
        }
        String value=JSON.toJSONString(body.get("value"));
        Integer result = permissionService.savePermissions(name,type,value);
        if(result==null||result.equals(0)){
            return ResponseEntity.status(403).body(Map.of("code",1001,"msg","请求错误！"));
        }
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(Map.of("code",1,"msg","请求成功！"));
    }
}
