package com.example.springauthservertest

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.ApplicationListener
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter

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
      .addFilterAt(
        AuthenticationWebFilter(authenticationManager)
          .apply {
            this.setServerAuthenticationConverter(serverAuthenticationConverter)
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
