package com.example.springauthservertest

import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class SuccessHandler(
  private val jwtTokenProvider: JwtTokenProvider
): ServerAuthenticationSuccessHandler {
  override fun onAuthenticationSuccess(
    webFilterExchange: WebFilterExchange,
    authentication: Authentication
  ): Mono<Void> {
    val token = this.jwtTokenProvider.generate(authentication.principal as String)
    webFilterExchange.exchange.response.headers.set("Authorization", token)
    println("Success!!!!!!!!!!!!!")
    return Mono.empty()
  }
}