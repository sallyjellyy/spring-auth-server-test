package com.example.springauthservertest

import com.fasterxml.jackson.annotation.JsonIgnore
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt
import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Transient
import org.springframework.data.mongodb.core.mapping.Document
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

@Document
data class CustomUser(
  @Id val id: String? = null,
  val secret: String,
  val key: String,
  val authenticated: Boolean = false,
//  private val principal: Jwt? = null,
):
//  Authentication,
  UserDetails {
//  override fun getName(): String = this.key
  override fun getUsername(): String = this.key
//  override fun getCredentials(): String = this.secret
  override fun getPassword(): String = this.secret
  override fun getAuthorities(): List<GrantedAuthority>? = null
//  override fun getDetails(): Any? = null
//  override fun getPrincipal(): Jwt = this.principal!!
//  override fun isAuthenticated(): Boolean = this.authenticated
//  override fun setAuthenticated(isAuthenticated: Boolean) {}
  override fun isAccountNonExpired(): Boolean = true
  override fun isAccountNonLocked(): Boolean = true
  override fun isCredentialsNonExpired(): Boolean = true
  override fun isEnabled(): Boolean = true
}