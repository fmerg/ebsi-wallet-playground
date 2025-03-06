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

// Global config
val EBSI_AGENT_ADRESS = "http://localhost:3000"


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


// DID resolution ------------------------------------

@Serializable
data class DidResolutionPayload(
    val did: String,
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


// Credential verification ---------------------------

@Serializable
data class CredentialVerificationPayload(
    val token: String,
)

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

suspend fun main() {

    // DID resolution
    val someDid = "did:ebsi:zwLFeK372v5tLJbU6U5xPoX"
    try {
        val document = resolveDid(someDid)
        println("\nSuccessfully resolved DID: $document")
    } catch (e: Exception) {
        println("\nCould not resolve DID: ${e.message}")
    }

    // Credential verification
    val vcToken = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZWJzaTp6d0xGZUszNzJ2NXRMSmJVNlU1eFBvWCNsbXZiOGtLOHJfVnUwRktWanlvaXJMNURDXzdoVm9UZkk3d2Z4cGtTVVFZIiwidHlwIjoiSldUIn0.eyJpYXQiOjE3NDEyNjE3NTksImV4cCI6MTg5OTAyODE1OSwianRpIjoidXJuOnV1aWQ6NzFhOTE1NTctYzZhOS00MDU4LTg2MWEtZDNhMzkyNDUyM2RiIiwic3ViIjoiZGlkOmVic2k6ejIzd2M0Q2dDOG9NWGZEZ2dDU3o0QzZCIiwiaXNzIjoiZGlkOmVic2k6endMRmVLMzcydjV0TEpiVTZVNXhQb1giLCJuYmYiOjE3NDEyNjE3NTksInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImlkIjoidXJuOnV1aWQ6NzFhOTE1NTctYzZhOS00MDU4LTg2MWEtZDNhMzkyNDUyM2RiIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZlcmlmaWFibGVBdHRlc3RhdGlvbiJdLCJpc3N1ZXIiOiJkaWQ6ZWJzaTp6d0xGZUszNzJ2NXRMSmJVNlU1eFBvWCIsImlzc3VhbmNlRGF0ZSI6IjIwMjUtMDMtMDZUMTE6NDk6MTkuOTI0WiIsImlzc3VlZCI6IjIwMjUtMDMtMDZUMTE6NDk6MTkuOTI0WiIsInZhbGlkRnJvbSI6IjIwMjUtMDMtMDZUMTE6NDk6MTkuOTI0WiIsInZhbGlkVW50aWwiOiIyMDM1LTAzLTA2VDExOjQ5OjE5LjkyNFoiLCJleHBpcmF0aW9uRGF0ZSI6IjIwMzAtMDMtMDZUMTE6NDk6MTkuOTI0WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmVic2k6ejIzd2M0Q2dDOG9NWGZEZ2dDU3o0QzZCIiwiZmlyc3ROYW1lIjoiQW1uYSIsImZhbWlseU5hbWUiOiJFbGhhZGkiLCJwZXJzb25hbElkZW50aWZpZXIiOjY2Njk5OSwiZGF0ZU9mQmlydGgiOiIxOTg4LTA3LTI2IiwiYWdlT3ZlcjE4Ijp0cnVlLCJnZW5kZXIiOiJ1bnNwZWNpZmllZCJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9hcGktcGlsb3QuZWJzaS5ldS90cnVzdGVkLXNjaGVtYXMtcmVnaXN0cnkvdjMvc2NoZW1hcy96RHBXR1VCZW5tcVh6dXJza3J5OU5zazZ2cTJSOHRoaDlWU2VvUnFndW95TUQiLCJ0eXBlIjoiRnVsbEpzb25TY2hlbWFWYWxpZGF0b3IyMDIxIn19fQ.kBUZWHW9khc1al-r7t-N41a_rckXbMYh1SASWD7BMRgQ51ZJvXc-L3NnLCB3mj84GB_WVhY9s2dtQLbnoVwdMw"
    try {
        val document = verifyCredential(vcToken)
        println("\nSuccessfully verified VC token: $document")
    } catch (e: Exception) {
        println("\nCould not verify VC token: ${e.message}")
    }
}
