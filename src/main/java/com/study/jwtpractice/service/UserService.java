package com.study.jwtpractice.service;

import com.study.jwtpractice.model.Role;
import com.study.jwtpractice.model.User;

import java.util.List;

public interface UserService {

    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();

}
