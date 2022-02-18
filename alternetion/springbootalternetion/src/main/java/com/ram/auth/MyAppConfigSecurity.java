package com.ram.auth;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class MyAppConfigSecurity extends WebSecurityConfigurerAdapter{

	@Autowired
	DataSource dataSource;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		
		
		auth.jdbcAuthentication()
		.dataSource(dataSource)
		.withDefaultSchema()
		.withUser("navi")
		.password(encoder.encode("navi"))
		.roles("USER")
		.and()
		.withUser("admin")
		.password(encoder.encode("admin"))
		.roles("ADMIN");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.authorizeRequests()
			.antMatchers("/Lobs").hasRole("ADMIN")
			.antMatchers("/lobs").hasRole("ADMIN,USER")
			.antMatchers("/lobs/{psaf_sys_id}").permitAll()
			.antMatchers("/lobs/{psaf_sys_id}").hasRole("ADMIN")
			.and().formLogin();
	}
	
	
	
	

}
