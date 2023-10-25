package com.example.springauthservertest

import org.springframework.data.mongodb.repository.MongoRepository
import org.springframework.stereotype.Repository

@Repository
interface CustomUserRepository: MongoRepository<CustomUser, String> {
  fun findByKey(username: String): CustomUser?
}