package com.java8.springboot2.controller;

import java.util.HashSet;
import java.util.Set;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.java8.springboot2.entity.Role;
import com.java8.springboot2.entity.RoleName;
import com.java8.springboot2.entity.User;
import com.java8.springboot2.model.LoginResponse;
import com.java8.springboot2.model.LoginRequest;
import com.java8.springboot2.model.WebApiGenericResponse;
import com.java8.springboot2.model.SignUpRequest;
import com.java8.springboot2.repository.RoleRepository;
import com.java8.springboot2.repository.UserRepository;
import com.java8.springboot2.security.jwt.JwtProvider;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtProvider jwtProvider;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		String jwt = jwtProvider.generateJwtToken(authentication);
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		return ResponseEntity.ok(new LoginResponse(jwt, userDetails.getUsername(), userDetails.getAuthorities()));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			
			return new ResponseEntity<>(new WebApiGenericResponse(Boolean.FALSE,"Fail -> Username is already taken!",null),
					HttpStatus.BAD_REQUEST);
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return new ResponseEntity<>(new WebApiGenericResponse(Boolean.FALSE,"Fail -> Email is already in use!",null),
					HttpStatus.BAD_REQUEST);
		}

		// Creating user's account
		User user = new User(signUpRequest.getName(), signUpRequest.getUsername(), signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		strRoles.forEach(role -> {
			switch (role) {
			case "admin":
				Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(adminRole);

				break;
			case "pm":
				Role pmRole = roleRepository.findByName(RoleName.ROLE_PM)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(pmRole);

				break;
			default:
				Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(userRole);
			}
		});

		user.setRoles(roles);
		userRepository.save(user);
		;
		return new ResponseEntity<>(new WebApiGenericResponse(Boolean.TRUE,"User registered successfully!",null), HttpStatus.OK);
	}
}