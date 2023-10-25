//package com.example.springauthservertest
//
//import org.springframework.context.annotation.Bean
//import org.springframework.security.authentication.AuthenticationProvider
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
//import org.springframework.security.core.Authentication
//import org.springframework.security.crypto.encrypt.TextEncryptor
//import org.springframework.security.crypto.password.PasswordEncoder
//import org.springframework.stereotype.Component
//
//@Component
//internal class CustomAuthenticationProvider(
//  private val userService: UserService,
////  private val textEncryptor: TextEncryptor,
//  private val passwordEncoder: PasswordEncoder
//): AuthenticationProvider {
//  override fun authenticate(authentication: Authentication): Authentication {
//    val key = authentication.name
//    val secret = authentication.credentials.toString()
////    val secret = this.textEncryptor.decrypt(authentication.credentials.toString())
//    val user = this.userService.loadUserByUsername(key)
//
//    if (user == null || user.secret == secret) {
//      throw Exception()
//    }
//
//    return user.copy(authenticated = true)
//  }
//
//  override fun supports(authentication: Class<*>?): Boolean =
//    authentication == UsernamePasswordAuthenticationToken::class.java
//}
