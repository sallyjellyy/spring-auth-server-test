package com.example.springauthservertest

import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.mapping.Document

@Document
data class Member(
  @Id val id: String? = null,
  val secret: String,
  val username: String,
  val type: SocialType = SocialType.NONE
) {
  enum class SocialType {
    NONE, GITHUB, GOOGLE
  }
}
