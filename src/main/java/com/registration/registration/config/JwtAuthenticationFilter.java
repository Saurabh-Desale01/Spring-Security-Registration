package com.registration.registration.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.registration.registration.repository.TokenRepository;
import com.registration.registration.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{
	
	//@Autowired
	private final JwtService jwtService;
	
	//@Autowired
	private final UserDetailsService userDetailsService;
	
	private final TokenRepository tokenRepository;

	@Override
	protected void doFilterInternal(@NotNull HttpServletRequest request, 
									@NotNull HttpServletResponse response, 
									@NotNull FilterChain filterChain)
			throws ServletException, IOException {
		
		final String authHeader = request.getHeader("Authorization");
		final String jwt;
		final String userEmail;
		
		if(authHeader == null || !authHeader.startsWith("Bearer ")) {
			//use to call next request
			filterChain.doFilter(request, response);
			return;
		}
		
		jwt = authHeader.substring(7);
		
		//use to extract userEmail/username from jwt token for validation purpose 
		userEmail = jwtService.extractUsername(jwt);
		
		//check username is authenticated or not
		if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetail = userDetailsService.loadUserByUsername(userEmail);
			var isTokenValid = tokenRepository.findByToken(jwt)
			          .map(t -> !t.isExpired() && !t.isRevoked())
			          .orElse(false);
			if(jwtService.isTokenValid(jwt, userDetail) && isTokenValid) {
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
						userDetail, null, userDetail.getAuthorities()
						);
				
				authToken.setDetails(new WebAuthenticationDetailsSource()
						.buildDetails(request));
				
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		
		filterChain.doFilter(request, response);
		
	}

}
