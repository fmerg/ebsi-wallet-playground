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

suspend fun main() {

    // DID resolution
    val someDid = "did:ebsi:zwLFeK372v5tLJbU6U5xPoX"
    try {
        val document = resolveDid(someDid)
        println("\nSuccessfully resolved DID: $document")
    } catch (e: Exception) {
        println("\nCould not resolve DID: ${e.message}")
    }
}
