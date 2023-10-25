package com.example.springauthservertest

import org.springframework.data.mongodb.repository.ReactiveMongoRepository
import org.springframework.stereotype.Repository
import reactor.core.publisher.Mono

@Repository
interface CustomUserRepository: ReactiveMongoRepository<CustomUser, String> {
  fun findByKey(username: String): Mono<CustomUser>
}