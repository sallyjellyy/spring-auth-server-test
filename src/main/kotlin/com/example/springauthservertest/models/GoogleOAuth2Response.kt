package com.example.springauthservertest.models

data class GoogleOAuth2Response(
  val email: String,
  val nickname: String,
  val profileUrl: String
) {
  companion object{
    fun from(attributes: Map<String, Any>): GoogleOAuth2Response =
      GoogleOAuth2Response(
        email = attributes["email"]!!.toString(),
        nickname = attributes["name"]!!.toString(),
        profileUrl = attributes["picture"]!!.toString()
      )

  }
    fun toPrincipal(): UserPrincipal =
      UserPrincipal(
        id = "",
        email = this.email,
        nickname = this.nickname,
        profileUrl = this.profileUrl,
        authorities = null,
        oAuth2Attributes = null
      )
}
