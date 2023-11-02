package com.example.springauthservertest.models

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User


data class UserPrincipal(
  val id:String,
  val email:String,
  val nickname:String,
  val profileUrl:String,
  val authorities: Collection<GrantedAuthority>,
  val oAuth2Attributes: Map<String, Any>
): OAuth2User, OidcUser {
  override fun getName(): String = this.nickname

  override fun getAttributes(): Map<String, Any> = this.oAuth2Attributes

  override fun getAuthorities(): Collection<GrantedAuthority> = this.authorities

  override fun getClaims(): Map<String, Any> = this.oAuth2Attributes

  override fun getUserInfo(): OidcUserInfo? = null

  override fun getIdToken(): OidcIdToken? = null
}
