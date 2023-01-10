package com.study.jwtpractice;

import com.study.jwtpractice.model.Role;
import com.study.jwtpractice.model.User;
import com.study.jwtpractice.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtPracticeApplication {

	// reference video lesson: https://youtu.be/VVn9OG9nfH0

	public static void main(String[] args) {
		SpringApplication.run(JwtPracticeApplication.class, args);
	}

	// TODO: create a permanent database instead of initializing it at each application run

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {

			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));

			userService.saveUser(new User(null, "Max", "fe_ax", "pass", new ArrayList<>()));
			userService.saveUser(new User(null, "Sasha", "vegan_appetite", "pass", new ArrayList<>()));

			userService.addRoleToUser("fe_ax", "ROLE_USER");
			userService.addRoleToUser("fe_ax", "ROLE_ADMIN");
			userService.addRoleToUser("vegan_appetite", "ROLE_USER");

		};
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
