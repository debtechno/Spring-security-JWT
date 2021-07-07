package com.auth.springAuthentication.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.springAuthentication.model.User;

public interface UserRepository extends JpaRepository<User, String> {
	
	public User findByUserId(String user_id);
	
	public User findByUserIdAndPassword(String user_id, String password);

}
