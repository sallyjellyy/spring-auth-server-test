package com.example.springauthservertest

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.stereotype.Component
import java.time.Instant
import java.util.Date

@Component
class JwtTokenProvider(
  @Value("\${security.key}")
  private val secretKey: String,
  private val rsaKey: RSAKey
) {
  private val signer = RSASSASigner(rsaKey)
  private val verifier = RSASSAVerifier(rsaKey.toPublicJWK())
  private val jwsHeader = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.keyID).build()

  fun generate(username: String): String {
    val claims = JWTClaimsSet.Builder()
      .subject(username)
      .issueTime(Date.from(Instant.now()))
      .issuer("cobalt")
      .expirationTime(Date.from(Instant.now().plusSeconds(1200)))
      .claim("email", "test@email.com")
      .build()

    val signedJWT = SignedJWT(jwsHeader, claims)
    signedJWT.sign(signer)

    return signedJWT.serialize()
  }

  fun getAuthentication(token: String): Authentication {
    val claimSet = SignedJWT.parse(token).jwtClaimsSet
    return UsernamePasswordAuthenticationToken(claimSet.subject, token, AuthorityUtils.NO_AUTHORITIES)
  }

  fun decode(token: String) {
    SignedJWT.parse(token).verify(verifier)
  }

  fun validateToken(token: String): Boolean =
    try {
      SignedJWT.parse(token).verify(verifier)
      true
    } catch (e: Exception) {
      false
    }
}