package com.example.springauthservertest.oauth

import com.example.springauthservertest.jwt.JwtTokenProvider
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.http.HttpHeaders
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component("OAuthSuccessHandler")
class OAuthSuccessHandler(
  private val jwtTokenProvider: JwtTokenProvider
): ServerAuthenticationSuccessHandler {
  override fun onAuthenticationSuccess(
    webFilterExchange: WebFilterExchange,
    authentication: Authentication
  ): Mono<Void> {
    println("oauth login succeeded")

    val oAuth2User = authentication.principal as OAuth2UserService.CustomOAuth2User
    val token = this.jwtTokenProvider.generate(oAuth2User.username)
    val response = webFilterExchange.exchange.response
    val buffer = response.bufferFactory().wrap(jacksonObjectMapper().writeValueAsBytes(mapOf("accessToken" to token)))
    response.headers.set(HttpHeaders.CONTENT_TYPE, "application/json; charset=UTF-8")

    return response.writeWith(Mono.just(buffer))
  }
}
