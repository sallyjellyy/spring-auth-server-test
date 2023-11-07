package com.example.springauthservertest

import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class MemberService(private val memberRepository: MemberRepository, private val passwordEncoder: PasswordEncoder) {
  fun findByUsername(username: String): Mono<Member> =
    this.memberRepository.findByUsername(username)

  fun join(username: String, password: String, type: Member.SocialType? = null): Mono<Member> =
    this.memberRepository.save(
      Member(
        username = username,
        secret = passwordEncoder.encode(password),
        type = type ?: Member.SocialType.NONE
      )
    )

  fun findSocialMember(type: Member.SocialType, username: String): Mono<Member> =
    this.memberRepository.findByUsername(username)
      .switchIfEmpty(this.join(username = username, password = "", type = type))
}
