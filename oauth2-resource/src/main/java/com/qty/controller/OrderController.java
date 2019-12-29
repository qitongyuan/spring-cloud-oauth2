package com.qty.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/order")
public class OrderController {

    @GetMapping(value = "/get")
    @PreAuthorize("hasAuthority('ROLE_USER')")//拥有p1权限方可访问此url
    public String get(){
        return "资源访问成功";
    }
}
