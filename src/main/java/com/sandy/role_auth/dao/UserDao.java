package com.sandy.role_auth.dao;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.sandy.role_auth.model.User;

@Repository
public interface UserDao extends JpaRepository<User , Integer>{
 List<User> findByUserEmail(String userEmail);
}
