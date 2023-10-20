//package com.example.authservertest
//
//import org.springframework.context.annotation.Bean
//import org.springframework.security.config.Customizer
//import org.springframework.security.config.annotation.web.builders.HttpSecurity
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
//import org.springframework.security.core.userdetails.User
//import org.springframework.security.core.userdetails.UserDetailsService
//import org.springframework.security.provisioning.InMemoryUserDetailsManager
//import org.springframework.security.web.SecurityFilterChain
//
//@EnableWebSecurity
//class DefaultSecurityConfig {
//  @Bean
//  @Throws(Exception::class)
//  fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain =
//    http.authorizeRequests {
//      it.anyRequest().authenticated()
//    }
//      .formLogin(Customizer.withDefaults())
//      .build()
//
//  @Bean
//  fun users(): UserDetailsService =
//    InMemoryUserDetailsManager(
//      User.withDefaultPasswordEncoder()
//        .username("admin")
//        .password("password")
//        .roles("USER")
//        .build()
//    )
//}