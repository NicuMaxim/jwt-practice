package com.study.jwtpractice;

import com.study.jwtpractice.model.Role;
import com.study.jwtpractice.model.User;
import com.study.jwtpractice.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;

@SpringBootApplication
public class JwtPracticeApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtPracticeApplication.class, args);
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {

			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));

			userService.saveUser(new User(null, "Max", "fe_ax", new ArrayList<>()));
			userService.saveUser(new User(null, "Sasha", "vegan_appetite", new ArrayList<>()));

			userService.addRoleToUser("fe_ax", "ROLE_USER");
			userService.addRoleToUser("fe_ax", "ROLE_ADMIN");
			userService.addRoleToUser("vegan_appetite", "ROLE_USER");

		};
	}

}
