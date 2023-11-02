package com.example.springauthservertest

import com.example.springauthservertest.models.PrincipalModel
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.http.HttpHeaders
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component("OAuthSuccessHandler")
class OAuthSuccessHandler(
  private val userRepository: CustomUserRepository,
  private val jwtTokenProvider: JwtTokenProvider
): ServerAuthenticationSuccessHandler {
  override fun onAuthenticationSuccess(
    webFilterExchange: WebFilterExchange,
    authentication: Authentication
  ): Mono<Void> {
    val username = (authentication.principal as PrincipalModel).attributes["email"]!!
    return this.userRepository.findByKey(username)
      .switchIfEmpty(this.userRepository.save(CustomUser(key = username, secret = "", authenticated = true)))
      .flatMap {
        val token = this.jwtTokenProvider.generate(username)
        val response = webFilterExchange.exchange.response
        val buffer = response.bufferFactory().wrap(jacksonObjectMapper().writeValueAsBytes(mapOf("accessToken" to token)))
        response.headers.set(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8")

        response.writeWith(Mono.just(buffer))
      }
  }
}
