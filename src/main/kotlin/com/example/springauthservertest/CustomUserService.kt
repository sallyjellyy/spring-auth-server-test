package com.example.springauthservertest

import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
internal class CustomUserService(
  private val userRepository: CustomUserRepository,
): ReactiveUserDetailsService {
  override fun findByUsername(username: String): Mono<UserDetails> {
    return this.userRepository.findByKey(username).cast(UserDetails::class.java)
  }
}
