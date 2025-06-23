package com.tpp.threat_perception_platform.permission;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PermissionController {

    @Autowired
    private PermissionCheckAspect permissionCheckAspect;

    @GetMapping("/check_permission/{path}")
    public ResponseEntity checkPermission(@PathVariable("path") String permission, HttpServletRequest request) {
        try{
            permissionCheckAspect.checkPermission(permission);
        } catch (SecurityException e){
            return ResponseEntity.status(403).body(e.getMessage());
        }
        return ResponseEntity.ok().build();
    }
}
