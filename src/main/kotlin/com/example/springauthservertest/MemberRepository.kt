package com.example.springauthservertest

import org.springframework.data.mongodb.repository.ReactiveMongoRepository
import org.springframework.stereotype.Repository
import reactor.core.publisher.Mono

@Repository
interface MemberRepository: ReactiveMongoRepository<Member, String> {
  fun findByUsername(username: String): Mono<Member>
}
