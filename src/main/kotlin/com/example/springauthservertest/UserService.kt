package com.example.springauthservertest

import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
internal class UserService(
  private val userRepository: CustomUserRepository,
  @Value("\${allowList}")
  private val allowList: Array<String>
): ReactiveUserDetailsService {
  override fun findByUsername(username: String): Mono<UserDetails> {
    allowList.forEach { println(it) }
    return this.userRepository.findByKey(username).cast(UserDetails::class.java)
  }
}
