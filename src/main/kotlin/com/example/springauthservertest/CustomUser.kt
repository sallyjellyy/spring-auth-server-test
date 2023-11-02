package com.example.springauthservertest

import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.mapping.Document
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

@Document
data class CustomUser(
  @Id val id: String? = null,
  val secret: String,
  val key: String,
  val authenticated: Boolean = false,
): UserDetails {
  override fun getUsername(): String = this.key
  override fun getPassword(): String = this.secret
  override fun getAuthorities(): List<GrantedAuthority>? = null
  override fun isAccountNonExpired(): Boolean = true
  override fun isAccountNonLocked(): Boolean = true
  override fun isCredentialsNonExpired(): Boolean = true
  override fun isEnabled(): Boolean = true
}