package com.auth.springAuthentication.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.auth.springAuthentication.model.User;
import com.auth.springAuthentication.repository.UserRepository;

@Service
public class MyUserDetailService implements UserDetailsService{
	
	@Autowired
	private UserRepository ur;

	@Override
	public User loadUserByUsername(String username) throws UsernameNotFoundException {		
		return ur.findByUserId(username);
	}
	
	public User save(User user) {
		ur.save(user);
		return user;
	}

}
