package com.study.jwtpractice.controller;

import com.study.jwtpractice.model.Role;
import com.study.jwtpractice.model.User;
import com.study.jwtpractice.service.UserServiceImpl;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class UserController {
    private final UserServiceImpl userService;

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        //wtf
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        //URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.ok().body(userService.saveRole(role));
    }

    @GetMapping("users/{username}")
    public ResponseEntity<User> getUser(@PathVariable String username) {
         return ResponseEntity.ok().body(userService.getUser(username));
    }

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers() {
        log.info("");
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PatchMapping("/role/addtouser")
    public ResponseEntity<?>addRoleToUser(@RequestBody RoleToUserForm form) {
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }



}

@Data
class RoleToUserForm {
    private String username;
    private String roleName;
}