package com.auth.springAuthentication.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

import com.auth.springAuthentication.model.AuthenticationRequest;
import com.auth.springAuthentication.model.AuthenticationResponse;
import com.auth.springAuthentication.model.User;
import com.auth.springAuthentication.repository.UserRepository;
import com.auth.springAuthentication.service.JwtUtil;
import com.auth.springAuthentication.service.MyUserDetailService;
import com.auth.springAuthentication.configure.SecurityConfigurer;
import com.auth.springAuthentication.filters.JwtRequestFilter;
import com.auth.springAuthentication.managers.SpringAuthenticationManager;


@CrossOrigin(origins="http://localhost:3000")
@RestController
@RequestMapping("/secure/auth")
@EnableWebSecurity
public class UserController{
	@Autowired	
	private AuthenticationManager am;
	@Autowired
	private UserRepository userRepository;	 
	@Autowired
	private JwtUtil jwtTokenUtil;
	@Autowired
	private MyUserDetailService ms;
		 
	@PostMapping("/user/add")
	public User save(@RequestBody User user) throws Exception{
		String userId = user.getUserId();
		if(userId != null && !userId.isEmpty()) {
			User userObj = ms.loadUserByUsername(userId);
			if(userObj != null) { 
				throw new Exception("user with "+userId+" already exist");
			}
		}
		User userObj = null;
		user.setStatus("active");
		String hashedPassword=generateHash(user.getPassword());
		user.setPassword(hashedPassword);
		userObj = ms.save(user);
		return userObj;	
	}
	
	@PostMapping("/loginUser")
	public User loginUser(@RequestBody User user) throws Exception {
		String userId = user.getUserId();
		String tempPassword = user.getPassword();		
		AuthenticationRequest ar=new AuthenticationRequest(user.getUserId(), 
				user.getPassword());
		ResponseEntity<?> userA=createAuthenticationToken(ar);
		Logger.global.info("The response entity is :"+userA);
		return user;
	}
	
	public String generateHash(String password) {
		BCryptPasswordEncoder bcryptPasswordEncoder = new BCryptPasswordEncoder();		
		return bcryptPasswordEncoder.encode(password);
	}
	
	
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest ar) throws Exception{
		try {	
		
			am.authenticate(new UsernamePasswordAuthenticationToken(ar.getUserId(), ar.getPassword()));
		} catch (BadCredentialsException e) {
			// TODO Auto-generated catch block
			throw new Exception("Incorrect username or password!"+e);
		}
		User user = new User();
		user.setUserId(ar.getUserId());
		final String jwt=jwtTokenUtil.generateToken(user);
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}

}
