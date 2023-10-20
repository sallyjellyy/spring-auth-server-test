package com.example.springauthservertest

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.UUID

@Configuration
class AuthServerConfig {
//  @Bean
//  fun filterChain(
//    http: HttpSecurity,
//    registeredClientRepository: RegisteredClientRepository,
//    authorizationService: OAuth2AuthorizationService,
//    jwtEncoder: JwtEncoder,
//    settings: AuthorizationServerSettings,
//  ): SecurityFilterChain {
//    OAuth2AuthorizationServerConfigurer()
//      .apply { http.apply(this) }
//      .registeredClientRepository(registeredClientRepository)
//      .authorizationService(authorizationService)
//      .tokenGenerator(JwtGenerator(jwtEncoder))
//      .authorizationServerSettings(settings)
//
//    // ResourceServer의 역할도 겸하기 위한 Security 기본 설정
//    http.csrf().disable()
//    http.securityContext()
//    http.authorizeHttpRequests()
//      .anyRequest().authenticated()
//
//    // jwt
//    http.oauth2ResourceServer()
//      .jwt()
//
//    return http.build()
//  }

  @Bean
  fun registeredClientRepository(): RegisteredClientRepository {
    val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("public-client")
      .clientSecret("{noop}secret")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .scope(OidcScopes.PROFILE)
      .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(2)).build()) // 토큰 2시간 유효
      .build()

    return InMemoryRegisteredClientRepository(registeredClient)
  }

  @Bean
  fun userDetailService(): UserDetailsService =
    InMemoryUserDetailsManager(
      User.withDefaultPasswordEncoder()
        .username("user")
        .password("password")
        .roles("USER")
        .build()
    )

//  @Bean
//  fun authorizationService(): OAuth2AuthorizationService = InMemoryOAuth2AuthorizationService()

  @Bean
  fun jwkSource(): JWKSource<SecurityContext> {
    val jwkSet = JWKSet(generateRsa())
    return ImmutableJWKSet(jwkSet)
  }

  private fun generateRsaKey(): KeyPair =
    KeyPairGenerator.getInstance("RSA")
      .apply { initialize(2048) }
      .generateKeyPair()

  private fun generateRsa(): RSAKey {
    val keyPair = generateRsaKey()
    val publicKey = keyPair.public as RSAPublicKey
    val privateKey = keyPair.private as RSAPrivateKey
    return RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build()
  }

  @Bean
  fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
    OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

  @Bean
  fun jwtEncoder(jwkSource: JWKSource<SecurityContext>): JwtEncoder =
    NimbusJwtEncoder(jwkSource)

  @Bean
  fun authorizationServerSettings(): AuthorizationServerSettings =
    AuthorizationServerSettings.builder()
      //      .tokenEndpoint("/token")
      .build()
}