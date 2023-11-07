package com.example.springauthservertest.login

import com.example.springauthservertest.jwt.JwtTokenProvider
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.http.HttpHeaders
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component("UsernamePasswordSuccessHandler")
class UsernamePasswordSuccessHandler(
  private val jwtTokenProvider: JwtTokenProvider
): ServerAuthenticationSuccessHandler {
  override fun onAuthenticationSuccess(
    webFilterExchange: WebFilterExchange,
    authentication: Authentication
  ): Mono<Void> {
    println("username password login succeeded")
    val token = this.jwtTokenProvider.generate(authentication.principal as String)
    val response = webFilterExchange.exchange.response
    val buffer = response.bufferFactory().wrap(jacksonObjectMapper().writeValueAsBytes(mapOf("accessToken" to token)))
    response.headers.set(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8")

    return response.writeWith(Mono.just(buffer))
  }
}
