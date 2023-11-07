package com.example.springauthservertest.jwt

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.stereotype.Component
import java.time.Instant
import java.util.Date

@Component
class JwtTokenProvider(
  private val rsaKey: RSAKey
) {
  private val signer = RSASSASigner(rsaKey.toPrivateKey())
  private val verifier = RSASSAVerifier(rsaKey)
  private val encrypter = RSAEncrypter(rsaKey)
  private val decrypter = RSADecrypter(rsaKey)
  private val jwsHeader = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.keyID).build()
  private val jweHeader =
    JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256).contentType("JWT").build()

  fun generate(username: String): String {
    val claims = JWTClaimsSet.Builder()
      .subject(username)
      .issueTime(Date.from(Instant.now()))
      .issuer("cobalt")
      .expirationTime(Date.from(Instant.now().plusSeconds(1200)))
      .claim("email", "test@email.com")
      .build()

    val signedJWT = SignedJWT(this.jwsHeader, claims)
    signedJWT.sign(this.signer)
    val encrypted = JWEObject(this.jweHeader, Payload(signedJWT))
    encrypted.encrypt(this.encrypter)
    return encrypted.serialize()
  }

  private fun getSignedJWT(token: String): SignedJWT {
    val jweObject = JWEObject.parse(token)
    jweObject.decrypt(this.decrypter)
    return jweObject.payload.toSignedJWT()
  }

  fun getAuthentication(token: String): Authentication {
    val claimSet = this.getSignedJWT(token).jwtClaimsSet
    return UsernamePasswordAuthenticationToken(claimSet.subject, token, AuthorityUtils.NO_AUTHORITIES)
  }

  fun validateToken(token: String): Boolean =
    try {
      val signed = this.getSignedJWT(token)
      signed.verify(verifier)
    } catch (e: Exception) {
      println(e)
      false
    }
}
