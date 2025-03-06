import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.Serializable


// HTTP helpers --------------------------------------

fun createHttpClient(): HttpClient {
    // Create HTTP client with JSON configuration
    val client = HttpClient(CIO) {
        install(ContentNegotiation) {
            json(Json {
                ignoreUnknownKeys = true
                prettyPrint = true
            })
        }
    }
    return client
}

suspend fun parseJsonResponse(resp: HttpResponse): JsonObject {
    val body = resp.bodyAsText()
    return Json.parseToJsonElement(body) as JsonObject
}


// Trusted execution environmen (quasi) --------------

fun loadPrivateKey(): JsonObject {
    // TODO: Properly plug to wallet
    val jwkString = """
        {
            "kty": "EC",
            "crv": "secp256k1",
            "x": "Wx21XTYt9Z7nZto9_-C0YcZYEAcZNDiV8VpPtWOlDIU",
            "y": "MmmrDYX7WuwI0B8lQt9Gjb8M-o8sdPvRBMQyS2kT8gc",
            "d": "-kUhyUS_wzwewAylJyWy6VKy2aWa1NhjnXvY3rZQDeQ"
        }
    """.trimIndent()
    return Json.parseToJsonElement(jwkString) as JsonObject
}


// EBSI Credential Flow operations (Basic API) -------

// Global config
val EBSI_AGENT_ADRESS = "http://localhost:3000"

// Payload data types

@Serializable
data class DidResolutionPayload(
    val did: String,
)

@Serializable
data class CredentialVerificationPayload(
    val token: String,
)

@Serializable
data class LocalIdentity(
    val did: String,
    val kid: String,
    val jwk: JsonObject,
)
@Serializable
data class PublicIdentity(
    val did: String,
    val kid: String? = null,
)

@Serializable
data class VerifiablePresentationPayload(
    val signer: LocalIdentity,
    val holder: PublicIdentity,
    val audience: PublicIdentity,
    val credentials: List<String>,
)

@Serializable
data class PresentationVerificationPayload(
    val token: String,
    val audience: PublicIdentity,
)


// Resolves the provided DID against the pilot EBSI Trust Registry. Throws
// exception in any case that the DID does not resolve (invalid DID format,
// non-registered DID, connection error etc.)
suspend fun resolveDid(did: String): JsonObject {
    val client = createHttpClient()
    val url = "$EBSI_AGENT_ADRESS/resolve-did"
    val payload = DidResolutionPayload(did = did)
    try {
      val resp: HttpResponse = client.get(url) {
          contentType(ContentType.Application.Json)
          setBody(payload)
      }
      val data = parseJsonResponse(resp)
      if (resp.status == HttpStatusCode.OK) {
          val document = data["didDocument"] as JsonObject
          return document
      } else {
          val error = data["error"].toString()
          throw Exception(error)
      }
    } catch (e: Exception) {
        throw e
    } finally {
        client.close()
    }
}


// Verifies the provided VC token against the pilot EBSI Trust Registry and
// retrieves the credential document. Throws exception in any case that the VC
// token does not verify (Invalid JWT format, non-registered DID, connection
// error etc.)
suspend fun verifyCredential(token: String): JsonObject {
    val client = createHttpClient()
    val url = "$EBSI_AGENT_ADRESS/verify-vc"
    val payload = CredentialVerificationPayload(token = token)
    try {
      val resp: HttpResponse = client.get(url) {
          contentType(ContentType.Application.Json)
          setBody(payload)
      }
      val data = parseJsonResponse(resp)
      if (resp.status == HttpStatusCode.OK) {
          val document = data["vcDocument"] as JsonObject
          return document
      } else {
          val error = data["error"].toString()
          throw Exception(error)
      }
    } catch (e: Exception) {
        throw e
    } finally {
        client.close()
    }
}


// Creates a VP token against the pilot EBSI Trust Registry for the provided
// credentials and identities. Throws exception in any case that the VP token
// is not created (Invalid JWT format, non-registered DIDs, connection error
// etc.)
suspend fun createVerifiablePresentation(
    signerDid: String,
    signerKid: String,
    signerJwk: JsonObject,
    holderDid: String,
    audienceDid: String,
    credentials: List<String>,
): String {
    val client = createHttpClient()
    val url = "$EBSI_AGENT_ADRESS/issue-vp"
    val payload = VerifiablePresentationPayload(
        signer = LocalIdentity(
            did = signerDid,
            kid = signerKid,
            jwk = signerJwk,
        ),
        holder = PublicIdentity(did = holderDid),
        audience = PublicIdentity(did = audienceDid),
        credentials = credentials,
    )
    try {
      val resp: HttpResponse = client.get(url) {
          contentType(ContentType.Application.Json)
          setBody(payload)
      }
      val data = parseJsonResponse(resp)
      if (resp.status == HttpStatusCode.OK) {
          val token = data["token"].toString()
          return token.replace("\"", "").replace("'", "")
      } else {
          val error = data["error"].toString()
          throw Exception(error)
      }
    } catch (e: Exception) {
        throw e
    } finally {
        client.close()
    }
}


// Verifies the provided VP token against the pilot EBSI Trust Registry and
// retrieves the credential document. Throws exception in any case that the VC
// token does not verify (Invalid JWT format, non-registered DID, connection
// error etc.)
suspend fun verifyPresentation(token: String, audienceDid: String): JsonObject {
    val client = createHttpClient()
    val url = "$EBSI_AGENT_ADRESS/verify-vp"
    val payload = PresentationVerificationPayload(
        token = token,
        audience = PublicIdentity(did = audienceDid),
    )
    try {
      val resp: HttpResponse = client.get(url) {
          contentType(ContentType.Application.Json)
          setBody(payload)
      }
      val data = parseJsonResponse(resp)
      if (resp.status == HttpStatusCode.OK) {
          val document = data["vpDocument"] as JsonObject
          return document
      } else {
          val error = data["error"].toString()
          throw Exception(error)
      }
    } catch (e: Exception) {
        throw e
    } finally {
        client.close()
    }
}


suspend fun main() {
    val holderDid = "did:ebsi:z23wc4CgC8oMXfDggCSz4C6B"
    val holderKid = "lk4lfYkT9imHJKH-cCqpX_qf6FZiP5RT48uuPfJLU9Y"
    val issuerDid = "did:ebsi:zwLFeK372v5tLJbU6U5xPoX"
    val verifierDid = "did:ebsi:z24acuDqgwY9qHjzEQ1r6YvF"


    // Resolve issuer DID (Wallet does not need to do that)
    try {
        val didDocument = resolveDid(issuerDid)
        println("\nSuccessfully resolved DID: $didDocument")
    } catch (e: Exception) {
        println("\nCould not resolve DID: ${e.message}")
    }

    // Received credential token
    val vcToken = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZWJzaTp6d0xGZUszNzJ2NXRMSmJVNlU1eFBvWCNsbXZiOGtLOHJfVnUwRktWanlvaXJMNURDXzdoVm9UZkk3d2Z4cGtTVVFZIiwidHlwIjoiSldUIn0.eyJpYXQiOjE3NDEyNjE3NTksImV4cCI6MTg5OTAyODE1OSwianRpIjoidXJuOnV1aWQ6NzFhOTE1NTctYzZhOS00MDU4LTg2MWEtZDNhMzkyNDUyM2RiIiwic3ViIjoiZGlkOmVic2k6ejIzd2M0Q2dDOG9NWGZEZ2dDU3o0QzZCIiwiaXNzIjoiZGlkOmVic2k6endMRmVLMzcydjV0TEpiVTZVNXhQb1giLCJuYmYiOjE3NDEyNjE3NTksInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImlkIjoidXJuOnV1aWQ6NzFhOTE1NTctYzZhOS00MDU4LTg2MWEtZDNhMzkyNDUyM2RiIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZlcmlmaWFibGVBdHRlc3RhdGlvbiJdLCJpc3N1ZXIiOiJkaWQ6ZWJzaTp6d0xGZUszNzJ2NXRMSmJVNlU1eFBvWCIsImlzc3VhbmNlRGF0ZSI6IjIwMjUtMDMtMDZUMTE6NDk6MTkuOTI0WiIsImlzc3VlZCI6IjIwMjUtMDMtMDZUMTE6NDk6MTkuOTI0WiIsInZhbGlkRnJvbSI6IjIwMjUtMDMtMDZUMTE6NDk6MTkuOTI0WiIsInZhbGlkVW50aWwiOiIyMDM1LTAzLTA2VDExOjQ5OjE5LjkyNFoiLCJleHBpcmF0aW9uRGF0ZSI6IjIwMzAtMDMtMDZUMTE6NDk6MTkuOTI0WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmVic2k6ejIzd2M0Q2dDOG9NWGZEZ2dDU3o0QzZCIiwiZmlyc3ROYW1lIjoiQW1uYSIsImZhbWlseU5hbWUiOiJFbGhhZGkiLCJwZXJzb25hbElkZW50aWZpZXIiOjY2Njk5OSwiZGF0ZU9mQmlydGgiOiIxOTg4LTA3LTI2IiwiYWdlT3ZlcjE4Ijp0cnVlLCJnZW5kZXIiOiJ1bnNwZWNpZmllZCJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9hcGktcGlsb3QuZWJzaS5ldS90cnVzdGVkLXNjaGVtYXMtcmVnaXN0cnkvdjMvc2NoZW1hcy96RHBXR1VCZW5tcVh6dXJza3J5OU5zazZ2cTJSOHRoaDlWU2VvUnFndW95TUQiLCJ0eXBlIjoiRnVsbEpzb25TY2hlbWFWYWxpZGF0b3IyMDIxIn19fQ.kBUZWHW9khc1al-r7t-N41a_rckXbMYh1SASWD7BMRgQ51ZJvXc-L3NnLCB3mj84GB_WVhY9s2dtQLbnoVwdMw"

    // Verify credential token
    try {
        val vcDocument = verifyCredential(vcToken)
        println("\nSuccessfully verified VC token: $vcDocument")
    } catch (e: Exception) {
        println("\nCould not verify VC token: ${e.message}")
    }

    // Display and store credential payload. Also save credential token for
    // later usage

    // Create verifiable presentation with the above saved credential token
    var vpToken = ""
    val holderJwk = loadPrivateKey()
    try {
        vpToken = createVerifiablePresentation(
            holderDid,
            holderKid,
            holderJwk,
            holderDid,
            verifierDid,
            listOf(vcToken),    // Could be more that one
        )
        println("\nSuccessfully created VP token: $vpToken")
    } catch (e: Exception) {
        println("\nCould not create VP token: ${e.message}")
    }

    // Send presentation token to the verfier. The wallet job ends here

    // Verify presentation (only for testing)
    try {
        val vpDocument = verifyPresentation(vpToken, verifierDid)
        println("\nSuccessfully verified VP token: $vpDocument")
    } catch (e: Exception) {
        println("\nCould not verify VP token: ${e.message}")
    }
}
