package com.example.springauthservertest.login

import com.example.springauthservertest.MemberService
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
internal class CustomUserService(private val memberService: MemberService): ReactiveUserDetailsService {
  override fun findByUsername(username: String): Mono<UserDetails> =
    this.memberService.findByUsername(username)
      .map { member ->
        User.builder()
          .username(member.username)
          .password(member.secret)
          .authorities("Member")
          .build()
      }
}
