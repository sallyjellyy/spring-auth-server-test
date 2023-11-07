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
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.web.server.WebFilter
import reactor.core.publisher.Mono

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
    authenticationManager: ReactiveAuthenticationManager,
    serverAuthenticationConverter: ServerAuthenticationConverter,
    @Qualifier("UsernamePasswordSuccessHandler")
    usernamePasswordSuccessHandler: ServerAuthenticationSuccessHandler,
    @Qualifier("OAuthSuccessHandler")
    oAuthSuccessHandler: ServerAuthenticationSuccessHandler,
    @Qualifier("JwtTokenAuthenticationFilter")
    jwtTokenAuthFilter: WebFilter,
//    oAuth2AuthorizationRequestResolver: ServerOAuth2AuthorizationRequestResolver
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
      .addFilterAt(jwtTokenAuthFilter, SecurityWebFiltersOrder.LOGOUT)
      .addFilterAt(
        AuthenticationWebFilter(authenticationManager)
          .apply {
            this.setRequiresAuthenticationMatcher(PathPatternParserServerWebExchangeMatcher("/username"))
            this.setServerAuthenticationConverter(serverAuthenticationConverter)
            this.setAuthenticationSuccessHandler(usernamePasswordSuccessHandler)
          },
        SecurityWebFiltersOrder.AUTHENTICATION
      )
      .oauth2Login {
//        it.authorizationRequestResolver(oAuth2AuthorizationRequestResolver)
//        it.authenticationMatcher(PathPatternParserServerWebExchangeMatcher("/oauth2/code/{registrationId}"))
        it.authenticationSuccessHandler(oAuthSuccessHandler)
      }
      .exceptionHandling {
//        it.authenticationEntryPoint(RedirectServerAuthenticationEntryPoint("/testing/oauth2"))
        it.accessDeniedHandler { exchange, exception ->
          println("access denied")
          Mono.error(Exception("access denied"))
        }
      }
      .build()
//
//  @Bean
//  fun authorizationRequestResolver(clientRegistrationRepository: ReactiveClientRegistrationRepository): ServerOAuth2AuthorizationRequestResolver =
//    DefaultServerOAuth2AuthorizationRequestResolver(
//      clientRegistrationRepository, PathPatternParserServerWebExchangeMatcher("/oauth/{registrationId}")
//    )
//
//  @Bean
//  fun clientRegistrationRepository(): ReactiveClientRegistrationRepository =
//    InMemoryReactiveClientRegistrationRepository(
//      listOf(
//        ClientRegistration.withRegistrationId("github")
//          .clientId("4225a0b60ae5b4e6c519")
//          .clientSecret("c7aecf39bacf8d319ebc519e08d42ccc311b2fef")
//          .scope("email")
//          .redirectUri("{basePath}/oauth2/code/github")
//          .authorizationUri("https://github.com/login/oauth/authorize")
//          .tokenUri("https://github.com/login/oauth/access_token")
//          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//          .build(),
//        ClientRegistration.withRegistrationId("google")
//          .clientId("1050889112752-9j0fkvsrnfuaap5h106omltqdip746ur.apps.googleusercontent.com")
//          .clientSecret("WB5vuxBQKhDyDupwunsnyotEU1j4")
//          .scope(listOf("email", "openid"))
//          .redirectUri("http://localhost:9001/login/oauth2/code/google")
//          .authorizationUri("https://github.com/login/oauth/authorize")
//          .tokenUri("https://github.com/login/oauth/access_token")
//          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//          .build()
//      )
//    )

  //  @Bean
  //  @Order(Ordered.HIGHEST_PRECEDENCE)
  //  fun oauthFilterChain(
  //    http: ServerHttpSecurity,
  //    @Qualifier("OAuthSuccessHandler")
  //    serverAuthenticationHandler: ServerAuthenticationSuccessHandler,
  //    @Qualifier("JwtTokenAuthenticationFilter")
  //    jwtTokenAuthFilter: WebFilter
  //  ): SecurityWebFilterChain =
  //    http
  //      //      .securityMatcher(PathPatternParserServerWebExchangeMatcher("/login"))
  //      .csrf { it.disable() }
  //      .httpBasic { it.disable() }
  //      .formLogin { it.disable() }
  //      .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
  //      .authorizeExchange {
  //        it.pathMatchers(*allowList).permitAll()
  //        it.anyExchange().authenticated()
  //      }
  //      .oauth2Login {
  //        it.authenticationSuccessHandler(serverAuthenticationHandler)
  //      }
  //      .addFilterAt(jwtTokenAuthFilter, SecurityWebFiltersOrder.LOGOUT)
  //      .build()

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
