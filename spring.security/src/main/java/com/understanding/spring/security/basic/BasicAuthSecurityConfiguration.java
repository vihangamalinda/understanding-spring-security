package com.understanding.spring.security.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION;

@Configuration
public class BasicAuthSecurityConfiguration {


    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> {
            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl) requests.anyRequest()).authenticated();
        });
//        http.formLogin(Customizer.withDefaults());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.httpBasic(Customizer.withDefaults());
        http.csrf().disable();
        http.headers().frameOptions().sameOrigin();
        return (SecurityFilterChain) http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        UserDetails userDetails = User.withUsername("user")
                .password("vihanga")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles("USER").build();
        UserDetails adminDetails = User.withUsername("admin")
                .password("admin")
                .passwordEncoder(str->passwordEncoder().encode(str))
                .roles("ADMIN","USER").build();

        JdbcUserDetailsManager jdbcUserDetailsManager =new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(userDetails);
        jdbcUserDetailsManager.createUser(adminDetails);

        return jdbcUserDetailsManager;
    }

    @Bean
    DataSource dataSource(){
        return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2).addScript(DEFAULT_USER_SCHEMA_DDL_LOCATION).build();
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
