package com.example.springauthservertest

import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class LoginService(
  private val jwtTokenProvider: JwtTokenProvider,
  private val authenticationManager: ReactiveAuthenticationManager
) {

  fun login(req: LoginReq): Mono<String> {
    val authentication = UsernamePasswordAuthenticationToken(req.username, req.password)
    return this.authenticationManager.authenticate(authentication)
      .map { this.jwtTokenProvider.generate(req.username) }
  }
}