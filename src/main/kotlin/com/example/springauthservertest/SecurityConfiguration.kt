package com.example.springauthservertest

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.ApplicationListener
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.server.SecurityWebFilterChain

@Configuration
@EnableWebFluxSecurity
class SecurityConfiguration(
    @Value("\${allowList}")
    private val allowList: Array<String>
) {
    @Bean
    fun filterChain(
        http: ServerHttpSecurity,
        authenticationProvider: AuthenticationProvider
    ): SecurityWebFilterChain {
        return http
            .authorizeExchange {
                it.pathMatchers(*allowList).authenticated()
                it.anyExchange().permitAll()
            }
            .httpBasic(Customizer.withDefaults())
            .authenticationManager(
                ReactiveAuthenticationManagerAdapter(ProviderManager(authenticationProvider))
            )
            .build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

    @Bean
    fun successEvent(): ApplicationListener<AuthenticationSuccessEvent> =
        ApplicationListener { e -> println("Success Login ${e.authentication.javaClass.name}") }

    @Bean
    fun failureEvent(): ApplicationListener<AuthenticationFailureBadCredentialsEvent> =
        ApplicationListener { e -> println("Bad Credential ${e.authentication.javaClass.name}") }
}