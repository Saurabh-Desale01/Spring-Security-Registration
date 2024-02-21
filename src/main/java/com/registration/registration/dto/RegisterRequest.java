package com.registration.registration.dto;

import com.registration.registration.entity.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
	
	private String firstName;
	private String lastName;
	private String emailId;
	private String password;
	private Role role;

}
