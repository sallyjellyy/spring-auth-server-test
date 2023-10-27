package com.example.springauthservertest

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.ApplicationListener
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.io.IOException

@Configuration
@EnableWebFluxSecurity
class SecurityConfiguration(
  @Value("\${allowList}")
  private val allowList: Array<String>
) {
  @Bean
  fun filterChain(
    http: ServerHttpSecurity,
    authenticationManager: ReactiveAuthenticationManager,
    serverAuthenticationConverter: ServerAuthenticationConverter
    //    authenticationProvider: AuthenticationProvider
  ): SecurityWebFilterChain {
    return http
      .csrf { it.disable() }
      .authorizeExchange {
        it.pathMatchers(*allowList).permitAll()
        it.anyExchange().authenticated()
      }
      .httpBasic { it.disable() }
      .formLogin { it.disable() }
      //      .authenticationManager(
      //        ReactiveAuthenticationManagerAdapter(ProviderManager(authenticationProvider))
      //      )
      .addFilterAt(
        AuthenticationWebFilter(authenticationManager)
          .apply {
            this.setServerAuthenticationConverter(serverAuthenticationConverter)
            this.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/user"))
          },
        SecurityWebFiltersOrder.AUTHENTICATION
      )
      .build()
  }

  @Bean
  fun authenticationManager(authenticationProvider: AuthenticationProvider): ReactiveAuthenticationManager =
    ReactiveAuthenticationManagerAdapter(ProviderManager(authenticationProvider))

  @Bean
  fun passwordEncoder(): PasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

  @Bean
  fun successEvent(): ApplicationListener<AuthenticationSuccessEvent> =
    ApplicationListener { e -> println("Success Login ${e.authentication.javaClass.name}") }

  @Bean
  fun failureEvent(): ApplicationListener<AuthenticationFailureBadCredentialsEvent> =
    ApplicationListener { e -> println("Bad Credential ${e.authentication.javaClass.name}") }
}