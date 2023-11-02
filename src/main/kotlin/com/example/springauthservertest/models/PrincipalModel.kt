package com.example.springauthservertest.models

data class PrincipalModel(
  val authorities: Set<Object>,
  val attributes: Map<String, String>,
  val nameAttributeKey: String
)
