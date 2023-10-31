package com.example.springauthservertest

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository
import org.springframework.web.server.WebFilter

@Configuration
@EnableWebFluxSecurity
class SecurityConfiguration(
  @Value("\${allowList}")
  private val allowList: Array<String>,
  @Value("\${security.key}")
  private val secretKey: String
) {
  @Bean
  fun filterChain(
    http: ServerHttpSecurity,
    //    authenticationManager: ReactiveAuthenticationManager,
    //    serverAuthenticationConverter: ServerAuthenticationConverter
    @Qualifier("JwtTokenAuthenticationFilter")
    jwtTokenAuthFilter: WebFilter
    //    authenticationProvider: AuthenticationProvider
  ): SecurityWebFilterChain {
    return http
      .csrf { it.disable() }
      .httpBasic { it.disable() }
      .formLogin { it.disable() }
      .authorizeExchange {
        it.pathMatchers(*allowList).permitAll()
        it.anyExchange().authenticated()
      }
      .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
      //      .authenticationManager(authenticationManager)
      //      .addFilterAt(
      //        AuthenticationWebFilter(authenticationManager)
      //          .apply {
      //            this.setServerAuthenticationConverter(serverAuthenticationConverter)
      //          },
      //        SecurityWebFiltersOrder.AUTHENTICATION
      //      )
      .addFilterAt(jwtTokenAuthFilter, SecurityWebFiltersOrder.AUTHENTICATION)
      .build()
  }

  //  @Bean
  //  fun authenticationManager(authenticationProvider: AuthenticationProvider): ReactiveAuthenticationManager =
  //    ReactiveAuthenticationManagerAdapter(ProviderManager(authenticationProvider))

  @Bean
  fun authenticationManager(
    userService: ReactiveUserDetailsService,
    passwordEncoder: PasswordEncoder
  ): ReactiveAuthenticationManager {
    var authenticationManager = UserDetailsRepositoryReactiveAuthenticationManager(userService)
    authenticationManager.setPasswordEncoder(passwordEncoder)
    return authenticationManager
  }

  @Bean
  fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

//  @Bean
//  fun keyPair(): KeyPair {
//    val keyStoreKeyFactory = KeyStoreKeyFactory(ClassPathResource("/cobalt-server.jks"), this.secretKey.toCharArray())
//    return keyStoreKeyFactory.getKeyPair("cobalt-server")
//  }

  @Bean
  fun jwsRSAKey(): RSAKey =
    RSAKeyGenerator(2048)
      .algorithm(JWSAlgorithm.RS256)
      .keyUse(KeyUse.SIGNATURE)
      .keyID("KEY_ID")
      .generate()
}
