package com.registration.registration.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.registration.registration.dto.AuthResponse;
import com.registration.registration.dto.LoginRequest;
import com.registration.registration.dto.RegisterRequest;
import com.registration.registration.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import java.io.IOException;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
	
	private final AuthService authService;

	@PostMapping("/register")
	public ResponseEntity<AuthResponse> registerUser(@RequestBody RegisterRequest registerRequest) {
		
		return ResponseEntity.ok(authService.registerUser(registerRequest));
	}
	
	@PostMapping("/login")
	public ResponseEntity<AuthResponse> loginUser(@RequestBody LoginRequest loginRequest) {
		
		return ResponseEntity.ok(authService.loginUser(loginRequest));
	}
	
	@PostMapping("/refresh-token")
	public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
		authService.refreshToken(request, response);
	}

	
}
