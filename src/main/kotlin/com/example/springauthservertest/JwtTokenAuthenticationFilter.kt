package com.example.springauthservertest

import org.springframework.http.HttpHeaders
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

@Component("JwtTokenAuthenticationFilter")
class JwtTokenAuthenticationFilter(
  private val tokenProvider: JwtTokenProvider
): WebFilter {
  override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
    val token = this.getTokenFromRequest(exchange.request)
    if (!token.isNullOrBlank() && this.tokenProvider.validateToken(token)) {
      val authentication = this.tokenProvider.getAuthentication(token)
      return chain.filter(exchange)
        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
    }
    return chain.filter(exchange)
  }

  private fun getTokenFromRequest(request: ServerHttpRequest): String? {
    val token = request.headers.getFirst(HttpHeaders.AUTHORIZATION)
    return token.takeIf { token != null && token.contains("Bearer ") }?.replace("Bearer ", "")
  }
}
