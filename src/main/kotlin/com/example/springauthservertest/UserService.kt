package com.example.springauthservertest

import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service

@Service
internal class UserService(
  private val userRepository: CustomUserRepository,
  @Value("\${allowList}")
  private val allowList: Array<String>
): UserDetailsService {
  override fun loadUserByUsername(username: String): CustomUser? {
    allowList.forEach { println(it) }
    return this.userRepository.findByKey(username)
  }
}