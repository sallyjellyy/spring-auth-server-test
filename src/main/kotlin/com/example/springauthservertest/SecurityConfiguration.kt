package com.example.springauthservertest

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.core.io.ClassPathResource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository
import org.springframework.web.server.WebFilter
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@Configuration
@EnableWebFluxSecurity
class SecurityConfiguration(
  @Value("\${allowList}")
  private val allowList: Array<String>,
  @Value("\${security.key}")
  private val secretKey: String
) {
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  fun filterChain(
    http: ServerHttpSecurity,
    authenticationManager: ReactiveAuthenticationManager,
    serverAuthenticationConverter: ServerAuthenticationConverter,
    serverAuthenticationSuccessHandler: ServerAuthenticationSuccessHandler,
    @Qualifier("JwtTokenAuthenticationFilter")
    jwtTokenAuthFilter: WebFilter
  ): SecurityWebFilterChain =
    http
      .csrf { it.disable() }
      .httpBasic { it.disable() }
      .formLogin { it.disable() }
      .authorizeExchange {
        it.pathMatchers(*allowList).permitAll()
        it.anyExchange().authenticated()
      }
      .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
      .addFilterAt(
        AuthenticationWebFilter(authenticationManager)
          .apply {
            this.setServerAuthenticationConverter(serverAuthenticationConverter)
            this.setAuthenticationSuccessHandler(serverAuthenticationSuccessHandler)
          },
        SecurityWebFiltersOrder.AUTHENTICATION
      )
      .addFilterAt(jwtTokenAuthFilter, SecurityWebFiltersOrder.AUTHENTICATION)
      .build()

  @Bean
  fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

  //  @Bean
  //  fun keyPair(): KeyPair {
  //    val keyStoreKeyFactory = KeyStoreKeyFactory(ClassPathResource("/cobalt-server.jks"), this.secretKey.toCharArray())
  //    return keyStoreKeyFactory.getKeyPair("cobalt-server")
  //  }

  @Bean
  fun jwsRSAKey(): RSAKey =
  //    RSAKey.Builder(keyPair.public as RSAPublicKey)
    //      .privateKey(keyPair.private as RSAPrivateKey)
    RSAKeyGenerator(2048)
      .algorithm(JWSAlgorithm.RS256)
      .keyUse(KeyUse.SIGNATURE)
      .keyID("KEY_ID")
      //      .build()
      .generate()
}
