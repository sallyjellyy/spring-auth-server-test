package com.example.springauthservertest.login

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
internal class CustomAuthenticationConverter: ServerAuthenticationConverter {
  override fun convert(exchange: ServerWebExchange): Mono<Authentication> =
    exchange.request.body
      .cache()
      .next()
      .flatMap { body ->
        val bodyBytes = ByteArray(body.capacity())
        body.read(bodyBytes);
        val bodyString = String(bodyBytes);
        body.readPosition(0);
        body.writePosition(0);
        body.write(bodyBytes);
        val mapper = jacksonObjectMapper()

        try {
          val loginRequest = mapper.readValue(bodyString, LoginRequest::class.java)

          Mono.just(
            UsernamePasswordAuthenticationToken(loginRequest.username, loginRequest.password)
          )
        } catch (e: Exception) {
          Mono.error(Exception(e.message))
        }
      }
}
