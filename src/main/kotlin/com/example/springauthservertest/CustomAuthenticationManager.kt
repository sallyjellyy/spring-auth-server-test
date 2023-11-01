package com.example.springauthservertest

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
internal class CustomAuthenticationProvider(
  private val customUserService: CustomUserService,
  private val passwordEncoder: PasswordEncoder
): ReactiveAuthenticationManager {
  override fun authenticate(authentication: Authentication): Mono<Authentication> {
    val key = authentication.name
    val secret = authentication.credentials.toString()

    return this.customUserService.findByUsername(key)
      .flatMap { user ->
        if (user == null || !passwordEncoder.matches(secret, user.password)) {
          Mono.error(Exception(""))
        } else {
          Mono.just(UsernamePasswordAuthenticationToken(user.username, secret, user.authorities))
        }
      }
  }
}
