package com.auth.springAuthentication.repository;

import javax.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import com.auth.springAuthentication.model.User;

public interface UserRepository extends JpaRepository<User, String> {
	
	public User findByUserId(String user_id);
	
	public User findByUserIdAndPassword(String user_id, String password);
	
	@Transactional
	@Modifying
	@Query(value="UPDATE login l SET l.password=?2 where l.user_id=?1", nativeQuery=true)
	public void encryptPassword(String user_id, String encodedPassword);

}
