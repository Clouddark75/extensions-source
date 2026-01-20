package eu.kanade.tachiyomi.extension.en.theblank

import android.util.Base64
import androidx.preference.PreferenceScreen
import androidx.preference.SwitchPreferenceCompat
import eu.kanade.tachiyomi.extension.en.theblank.decryption.SecretStream
import eu.kanade.tachiyomi.extension.en.theblank.decryption.State
import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.network.POST
import eu.kanade.tachiyomi.network.interceptor.rateLimit
import eu.kanade.tachiyomi.source.ConfigurableSource
import eu.kanade.tachiyomi.source.model.Filter
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.MangasPage
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.online.HttpSource
import eu.kanade.tachiyomi.util.asJsoup
import keiyoushi.utils.firstInstance
import keiyoushi.utils.firstInstanceOrNull
import keiyoushi.utils.getPreferencesLazy
import keiyoushi.utils.parseAs
import keiyoushi.utils.toJsonString
import keiyoushi.utils.tryParse
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.asResponseBody
import okio.Buffer
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.text.SimpleDateFormat
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

class TheBlank : HttpSource(), ConfigurableSource {
    override val name = "The Blank"
    override val lang = "en"
    override val baseUrl = "https://theblank.net"
    private val baseHttpUrl = baseUrl.toHttpUrl()
    override val versionId = 2
    override val supportsLatest = true
    private val preferences by getPreferencesLazy()

    override val client = network.cloudflareClient.newBuilder()
        .addInterceptor { chain ->
            val request = chain.request()
            return@addInterceptor if (request.url.fragment == THUMBNAIL_FRAGMENT) {
                thumbnailClient.newCall(request).execute()
            } else {
                chain.proceed(request)
            }
        }
        .addInterceptor(::imageInterceptor)
        .rateLimit(1)
        .build()

    private val thumbnailClient = network.cloudflareClient

    override fun headersBuilder() = super.headersBuilder()
        .set("Origin", "https://${baseHttpUrl.host}")
        .set("Referer", "$baseUrl/")

    private var version: String? = null
    private var csrfToken: String? = null

    @Synchronized
    private fun apiRequest(
        url: HttpUrl,
        body: RequestBody? = null,
        includeXSRFToken: Boolean,
        includeCSRFToken: Boolean,
        includeVersion: Boolean,
    ): Request {
        var xsrfToken = client.cookieJar.loadForRequest(baseHttpUrl)
            .firstOrNull { it.name == "XSRF-TOKEN" }?.value

        if (
            (includeXSRFToken && xsrfToken == null) ||
            (includeCSRFToken && csrfToken == null) ||
            (includeVersion && version == null)
        ) {
            val document = client.newCall(GET(baseHttpUrl, headers)).execute()
                .also {
                    if (!it.isSuccessful) {
                        it.close()
                        throw Exception("HTTP Error ${it.code}")
                    }
                }
                .asJsoup()

            version = document.selectFirst("#app")!!
                .attr("data-page")
                .parseAs<Version>().version

            csrfToken = document.selectFirst("meta[name=csrf-token]")!!
                .attr("content")

            xsrfToken = client.cookieJar.loadForRequest(baseHttpUrl)
                .first { it.name == "XSRF-TOKEN" }.value
        }

        val headers = headersBuilder().apply {
            set("Accept", "application/json")
            set("X-Requested-With", "XMLHttpRequest")
            if (includeVersion) {
                set("X-Inertia", "true")
                set("X-Inertia-Version", version!!)
            }
            if (includeXSRFToken) {
                set("X-XSRF-TOKEN", xsrfToken!!)
            }
            if (includeCSRFToken) {
                set("X-CSRF-TOKEN", csrfToken!!)
            }
        }.build()

        return if (body != null) {
            POST(url.toString(), headers, body)
        } else {
            GET(url, headers)
        }
    }

    override fun popularMangaRequest(page: Int) =
        searchMangaRequest(page, "", SortFilter.popular)

    override fun popularMangaParse(response: Response) =
        searchMangaParse(response)

    override fun latestUpdatesRequest(page: Int) =
        searchMangaRequest(page, "", SortFilter.latest)

    override fun latestUpdatesParse(response: Response) =
        searchMangaParse(response)

    override fun searchMangaRequest(page: Int, query: String, filters: FilterList): Request {
        if (query.isNotEmpty()) {
            val url = baseHttpUrl.newBuilder().apply {
                addPathSegments("api/v1/search/series")
                addQueryParameter("q", query)
            }.build()

            return apiRequest(url, includeXSRFToken = true, includeCSRFToken = false, includeVersion = false)
        }

        val url = baseHttpUrl.newBuilder().apply {
            addPathSegment("library")
            if (page > 1) {
                addQueryParameter("page", page.toString())
            }
            filters.firstInstanceOrNull<GenreFilter>()?.also { genre ->
                genre.included.also { included ->
                    if (included.isNotEmpty()) {
                        addQueryParameter("include_genres", included.joinToString(","))
                    }
                }
                genre.excluded.also { excluded ->
                    if (excluded.isNotEmpty()) {
                        addQueryParameter("exclude_genres", excluded.joinToString(","))
                    }
                }
            }
            filters.firstInstanceOrNull<TypeFilter>()?.also { type ->
                type.included.also { included ->
                    if (included.isNotEmpty()) {
                        addQueryParameter("include_types", included.joinToString(","))
                    }
                }
                type.excluded.also { excluded ->
                    if (excluded.isNotEmpty()) {
                        addQueryParameter("exclude_types", excluded.joinToString(","))
                    }
                }
            }
            filters.firstInstanceOrNull<StatusFilter>()?.also { status ->
                if (status.checked.isNotEmpty()) {
                    addQueryParameter("status", status.checked.joinToString(","))
                }
            }
            filters.firstInstance<SortFilter>().also { sort ->
                addQueryParameter("orderby", sort.sort)
                if (sort.ascending) {
                    addQueryParameter("order", "asc")
                }
            }
        }.build()

        return apiRequest(url, includeXSRFToken = true, includeCSRFToken = false, includeVersion = false)
    }

    override fun getFilterList() = FilterList(
        Filter.Header("Text search ignores filters!"),
        Filter.Separator(),
        SortFilter(),
        GenreFilter(),
        TypeFilter(),
        StatusFilter(),
    )

    override fun searchMangaParse(response: Response): MangasPage {
        if (response.request.url.queryParameter("q") != null) {
            val data = response.parseAs<List<BrowseManga>>()

            return MangasPage(
                mangas = data.map { it.toSManga(::createThumbnailUrl) },
                hasNextPage = false,
            )
        } else {
            val data = response.parseAs<LibraryResponse>().series

            return MangasPage(
                mangas = data.data.map { it.toSManga(::createThumbnailUrl) },
                hasNextPage = data.meta.current < data.meta.last,
            )
        }
    }

    override fun mangaDetailsRequest(manga: SManga): Request {
        val url = baseUrl.toHttpUrl().newBuilder()
            .addPathSegment("serie")
            .addPathSegment(manga.url)
            .build()

        return apiRequest(url, includeXSRFToken = true, includeCSRFToken = false, includeVersion = true)
    }

    override fun getMangaUrl(manga: SManga): String {
        return "$baseUrl/serie/${manga.url}"
    }

    override fun mangaDetailsParse(response: Response): SManga {
        val data = response.parseAs<MangaResponse>().props.serie

        return SManga.create().apply {
            url = data.slug
            title = data.title
            thumbnail_url = createThumbnailUrl(data.image)
            author = data.author
            artist = data.artist
            description = buildString {
                data.description?.also {
                    append(it.trim(), "\n\n")
                }
                data.releaseYear?.also {
                    append("Release: ", it, "\n\n")
                }
                data.alternativeName?.also {
                    append("Alternative name: ", it)
                }
            }.trim()
            genre = buildList {
                data.type?.name?.also(::add)
                data.genres.mapTo(this) { it.name }
            }.joinToString()
            status = when (data.status) {
                "ongoing", "upcoming" -> SManga.ONGOING
                "finished" -> SManga.COMPLETED
                "dropped" -> SManga.CANCELLED
                "onhold" -> SManga.ON_HIATUS
                else -> SManga.UNKNOWN
            }
        }
    }

    private fun createThumbnailUrl(imagePath: String?): String? {
        return baseHttpUrl.newBuilder()
            .encodedPath(imagePath ?: return null)
            .fragment(THUMBNAIL_FRAGMENT)
            .toString()
    }

    override fun chapterListRequest(manga: SManga) =
        mangaDetailsRequest(manga)

    override fun chapterListParse(response: Response): List<SChapter> {
        val data = response.parseAs<MangaResponse>().props.serie
        val hidePremium = preferences.getBoolean(HIDE_PREMIUM_PREF, false)

        return data.chapters
            .filter { !(it.isPremium && hidePremium) }
            .map {
                SChapter.create().apply {
                    url = baseUrl.toHttpUrl().newBuilder().apply {
                        addPathSegment("serie")
                        addPathSegment(data.slug)
                        addPathSegment("chapter")
                        addPathSegment(it.slug)
                    }.build().encodedPath
                    name = buildString {
                        if (it.isPremium) {
                            append("\uD83D\uDD12 ") // lock emoji
                        }
                        append(it.title)
                    }
                    date_upload = dateFormat.tryParse(it.createdAt)
                }
            }.asReversed()
    }

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'", Locale.ROOT)

    override fun setupPreferenceScreen(screen: PreferenceScreen) {
        SwitchPreferenceCompat(screen.context).apply {
            key = HIDE_PREMIUM_PREF
            title = "Hide Premium Chapters"
            setDefaultValue(false)
        }.also(screen::addPreference)
    }

    override fun pageListRequest(chapter: SChapter): Request {
        val url = "$baseUrl${chapter.url}".toHttpUrl()

        return apiRequest(url, includeXSRFToken = true, includeCSRFToken = false, includeVersion = true)
    }

    override fun pageListParse(response: Response): List<Page> {
        val signedUrls = response.parseAs<PageListResponse>().props.signedUrls

        val keyPair = generateKeyPair()
        val sid = decodeUrlSafeBase64(
            fetchSessionId(keyPair.publicKeyBase64),
        )
        val sessionKey = rsaDecrypt(keyPair.keyPair.private, sid)

        return signedUrls.mapIndexed { idx, img ->
            Page(
                index = idx,
                imageUrl = img.toHttpUrl().newBuilder()
                    .fragment(sessionKey)
                    .build()
                    .toString(),
            )
        }
    }

    private fun fetchSessionId(publicKeyBase64: String): String {
        val url = "$baseUrl/api/v1/session".toHttpUrl()
        val body = buildJsonObject {
            put("clientPublicKey", publicKeyBase64)
            put("nonce", generateNonce())
        }.toJsonString().toRequestBody("application/json".toMediaType())

        val request = apiRequest(url, body, includeXSRFToken = true, includeCSRFToken = true, includeVersion = false)

        val response = client.newCall(request).execute()
        if (!response.isSuccessful) {
            val errorBody = response.body.string()
            response.close()
            throw Exception("Session API error: ${response.code} - $errorBody")
        }

        return response.parseAs<SessionResponse>().sid
    }

    private fun generateKeyPair(): KeyPairResult {
        val generator = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }

        val keyPair = generator.generateKeyPair()
        val publicKeyBase64 = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)

        return KeyPairResult(keyPair, publicKeyBase64)
    }

    private val secureRandom = SecureRandom()

    private fun generateNonce(): String {
        val timestampHex = (System.currentTimeMillis() / 1000)
            .toString(16)
            .padStart(16, '0')

        val randomHex = ByteArray(24).apply {
            secureRandom.nextBytes(this)
        }.joinToString("") { "%02x".format(it) }

        return timestampHex + randomHex
    }

    private fun rsaDecrypt(privateKey: PrivateKey, encryptedData: ByteArray): String {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding").apply {
            val oaepSpec = OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT,
            )

            init(Cipher.DECRYPT_MODE, privateKey, oaepSpec)
        }

        val decryptedBytes = cipher.doFinal(encryptedData)

        return String(decryptedBytes, StandardCharsets.UTF_8)
    }

    private fun decodeUrlSafeBase64(data: String): ByteArray {
        val normalized = data
            .replace('-', '+')
            .replace('_', '/')
            .let { it + "=".repeat((4 - it.length % 4) % 4) }

        return Base64.decode(normalized, Base64.DEFAULT)
    }

    private fun imageInterceptor(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val response = chain.proceed(request)

        val fragment = request.url.fragment
            ?.takeIf { it != THUMBNAIL_FRAGMENT }
            ?: return response
        val headerNonce = response.header("x-stream-header")
            ?: return response

        return try {
            val nonce = decodeUrlSafeBase64(headerNonce)
            if (nonce.size != 24) {
                throw IOException("Invalid nonce size: ${nonce.size}, expected 24")
            }

            // CRITICAL: Hash the session key (fragment) with SHA-256 to get the actual encryption key
            val key = MessageDigest.getInstance("SHA-256")
                .digest(fragment.toByteArray(Charsets.UTF_8))
            if (key.size != 32) {
                throw IOException("Invalid key size: ${key.size}, expected 32")
            }

            android.util.Log.d("TheBlank", "Fragment (session key): $fragment")
            android.util.Log.d("TheBlank", "Header nonce (base64): $headerNonce")
            android.util.Log.d("TheBlank", "Nonce (hex): ${nonce.joinToString("") { "%02x".format(it) }}")
            android.util.Log.d("TheBlank", "Key (hex): ${key.joinToString("") { "%02x".format(it) }}")

            // Read the entire encrypted stream into memory
            val encryptedBuffer = Buffer()
            val source = response.body.source()
            var totalRead = 0L
            val bufferSize = 8192L

            while (true) {
                val bytesRead = source.read(encryptedBuffer, bufferSize)
                if (bytesRead == -1L) break
                totalRead += bytesRead
            }

            val encryptedData = encryptedBuffer.readByteArray()
            android.util.Log.d("TheBlank", "Total encrypted data size: ${encryptedData.size} bytes")

            // Initialize decryption state
            val secretStream = SecretStream()
            val state = State()
            val initResult = secretStream.initPull(state, nonce, key)
            if (initResult != 0) {
                throw IOException("Failed to initialize decryption stream")
            }
            android.util.Log.d("TheBlank", "Stream initialized successfully")

            // Decrypt all chunks
            val decryptedChunks = mutableListOf<ByteArray>()
            var offset = 0
            var chunkCount = 0
            val chunkSize = CHUNK_SIZE

            while (offset < encryptedData.size) {
                // Calculate this chunk's size (might be smaller for the last chunk)
                val remainingBytes = encryptedData.size - offset
                val currentChunkSize = minOf(chunkSize, remainingBytes)

                // Extract the chunk
                val chunk = encryptedData.copyOfRange(offset, offset + currentChunkSize)

                chunkCount++
                android.util.Log.d("TheBlank", "Processing chunk $chunkCount: size=${chunk.size} bytes, offset=$offset")

                // Log first few bytes of the chunk for debugging
                val preview = chunk.take(32).joinToString(" ") { "%02x".format(it) }
                android.util.Log.d("TheBlank", "Chunk $chunkCount first 32 bytes: $preview")

                if (chunk.size >= 17) {
                    val macPreview = chunk.takeLast(16).joinToString(" ") { "%02x".format(it) }
                    android.util.Log.d("TheBlank", "Chunk $chunkCount MAC (last 16 bytes): $macPreview")
                }

                // Decrypt the chunk
                val result = secretStream.pull(state, chunk, chunk.size)
                if (result == null) {
                    android.util.Log.e("TheBlank", "Decryption failed for chunk $chunkCount (size=${chunk.size})")
                    android.util.Log.e("TheBlank", "First 32 bytes: $preview")
                    throw IOException("Decrypt failed at chunk $chunkCount")
                }

                android.util.Log.d("TheBlank", "Chunk $chunkCount decrypted: ${result.message.size} bytes, tag=0x${result.tag.toString(16)}")
                decryptedChunks.add(result.message)

                // Move to next chunk
                offset += currentChunkSize

                // Check if this was the final chunk
                if (result.tag.toInt() == SecretStream.TAG_FINAL) {
                    android.util.Log.d("TheBlank", "Final tag received at chunk $chunkCount")
                    break
                }
            }

            // Combine all decrypted chunks
            val totalSize = decryptedChunks.sumOf { it.size }
            val decryptedData = ByteArray(totalSize)
            var position = 0
            for (chunk in decryptedChunks) {
                chunk.copyInto(decryptedData, position)
                position += chunk.size
            }

            android.util.Log.d("TheBlank", "Successfully decrypted ${decryptedChunks.size} chunks, total size: ${decryptedData.size} bytes")

            // Create a new response with the decrypted data
            val decryptedSource = Buffer().apply { write(decryptedData) }

            response.newBuilder()
                .body(decryptedSource.asResponseBody("image/jpeg".toMediaType()))
                .build()
        } catch (e: Exception) {
            android.util.Log.e("TheBlank", "Image decryption error", e)
            throw IOException("Image decryption error: ${e.message}", e)
        }
    }

    override fun imageUrlParse(response: Response): String {
        throw UnsupportedOperationException()
    }
}

private const val THUMBNAIL_FRAGMENT = "thumbnail"
private const val HIDE_PREMIUM_PREF = "pref_hide_premium_chapters"
private const val CHUNK_SIZE = 65552 // 1 (tag) + 65535 (data) + 16 (MAC)
private const val ABYTES = 16 // MAC only (tag is separate)
