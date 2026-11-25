
package eu.kanade.tachiyomi.extension.es.aedex

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Rect
import keiyoushi.network.Fetch
import keiyoushi.network.fetch
import keiyoushi.utils.parseAs
import keiyoushi.utils.toJsonRequestBody
import okhttp3.Interceptor
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.asResponseBody
import okio.Buffer
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Clock

// Pages of the free reader: signed requests, XOR-masked images, shuffled over an 8x8 grid when the page has a key
class ImageInterceptor(
    // A new visit to the reader for a chapter, given the seed of the stale one
    private val renewSession: (chapterKey: String, staleSeed: String) -> ReaderSession?,
) : Interceptor {

    private val liveTokens = ConcurrentHashMap<String, LiveToken>()

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val fragment = request.url.fragment
        if (fragment == null || request.url.pathSegments.take(2) != listOf("lector", "p")) return chain.proceed(request)

        val parts = fragment.split(':', limit = 8)
        val keys = VisitKeys.parse(parts)
        val hasTrailerKey = parts.size >= 8
        val hasXorByte = parts.size >= 7
        val index = parts[
            if (hasTrailerKey) {
                6
            } else if (hasXorByte) {
                5
            } else {
                4
            },
        ].toInt()
        val chapterKey = parts[
            if (hasTrailerKey) {
                7
            } else if (hasXorByte) {
                6
            } else {
                5
            },
        ]

        var currentRequest = request
        var currentKeys = keys
        var attempts = 0
        var renewed = false

        while (true) {
            val response = try {
                proceedPage(chain, currentRequest, currentKeys)
            } catch (_: OutdatedVisitException) {
                if (renewed) throw OutdatedVisitException()
                val session = renewSession(chapterKey, currentKeys.seed)
                    ?.takeIf { index < it.pageCount }
                    ?: throw OutdatedVisitException()
                currentRequest = request.newBuilder()
                    .url(session.imageUrl(index, chapterKey))
                    .fetch(Fetch.XHR.from(session.readerUrl))
                    .build()
                currentKeys = session.keys
                attempts = 0
                renewed = true
                continue
            } catch (e: IOException) {
                if (attempts >= MAX_ATTEMPTS - 1) throw e
                attempts++
                retryDelay(attempts)
                currentRequest = retryRequest(currentRequest, attempts)
                continue
            }

            when {
                response.code == 401 || response.code == 410 -> {
                    response.close()
                    throw IOException("La sesión de lectura expiró. Vuelve a abrir el capítulo")
                }

                response.code == 403 -> {
                    response.close()
                    liveTokens.remove(currentKeys.liveKey)
                    if (attempts >= MAX_ATTEMPTS - 1) throw IOException("HTTP 403")
                    attempts++
                    retryDelay(attempts)
                    currentRequest = retryRequest(currentRequest, attempts)
                }

                !response.isSuccessful -> {
                    val code = response.code
                    response.close()
                    if (attempts >= MAX_ATTEMPTS - 1) throw IOException("HTTP error $code")
                    attempts++
                    retryDelay(attempts)
                    currentRequest = retryRequest(currentRequest, attempts)
                }

                else -> return processPage(response, currentKeys, request.url.pathSegments[2])
            }
        }
    }

    private fun processPage(response: Response, keys: VisitKeys, handle: String): Response {
        val contentType = response.body.contentType()
        val rawBytes = response.body.bytes()

        val trailerKey = keys.trailerKey.ifBlank { keys.token }
        val trailer = extractTrailer(rawBytes, trailerKey, handle)

        val cleanLen = trailer?.cleanLen ?: rawBytes.size
        val pageXorKey = trailer?.xorKey
            ?: response.header("X-Page-Xor")?.toIntOrNull()
                ?.takeIf { it != 0 }
            ?: keys.xorByte

        val scrambleKey = trailer?.key
            ?: response.header("X-Page-Key").orEmpty().toByteArray(Charsets.UTF_8)

        val rawGutter = trailer?.gutter
            ?: response.header("X-Tile-Gutter")?.toIntOrNull()
            ?: 0
        val tileGutter = rawGutter.takeIf { it in 1 until 64 } ?: 0

        val header = rawBytes.copyOfRange(0, minOf(HEADER_SIZE, cleanLen))
        var xorKey = if (trailer != null) {
            pageXorKey
        } else if (isImageHeader(header)) {
            0
        } else {
            pageXorKey
        }

        if (trailer == null && xorKey != 0 && !isImageHeader(header.xor(xorKey)) && xorKey != LEGACY_XOR_KEY) {
            xorKey = LEGACY_XOR_KEY
        }

        if (!isImageHeader(header.xor(xorKey))) {
            response.close()
            throw IOException("Unknown page image format")
        }

        val plainBytes = rawBytes.copyOf(cleanLen)
        if (xorKey != 0) {
            for (i in plainBytes.indices) {
                plainBytes[i] = (plainBytes[i].toInt() xor xorKey).toByte()
            }
        }

        if (scrambleKey.isEmpty()) {
            return responseWithBytes(response, plainBytes, contentType)
        }

        val image = BitmapFactory.decodeByteArray(plainBytes, 0, plainBytes.size)
            ?: throw IOException("Undecodable page image")

        val gutter = if (
            tileGutter > 0 &&
            image.width - 16 * tileGutter >= MIN_IMAGE_SIZE &&
            image.height - 16 * tileGutter >= MIN_IMAGE_SIZE
        ) {
            tileGutter
        } else {
            0
        }

        val result = try {
            val outputWidth = image.width - gutter * 16
            val outputHeight = image.height - gutter * 16
            val bitmap = Bitmap.createBitmap(outputWidth, outputHeight, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bitmap)
            val paint = Paint().apply {
                isFilterBitmap = false
                isAntiAlias = false
                isDither = false
            }

            val slices = AedexSlicePlanner(scrambleKey, image.width, image.height, gutter).slices()
            for (slice in slices) {
                canvas.drawBitmap(
                    image,
                    Rect(slice.sx, slice.sy, slice.sx + slice.sw, slice.sy + slice.sh),
                    Rect(slice.dx, slice.dy, slice.dx + slice.sw, slice.dy + slice.sh),
                    paint,
                )
            }

            bitmap
        } finally {
            image.recycle()
        }

        val buffer = Buffer()
        try {
            if (!result.compress(Bitmap.CompressFormat.JPEG, 95, buffer.outputStream())) {
                throw IOException("Unable to compress reconstructed page")
            }
        } finally {
            result.recycle()
        }

        return response.newBuilder()
            .body(buffer.asResponseBody(MEDIA_TYPE, buffer.size))
            .build()
    }

    private fun extractTrailer(bytes: ByteArray, trailerKey: String, handle: String): PageTrailer? {
        if (bytes.size < TRAILER_SUFFIX_SIZE) return null

        val trailerLength = ((bytes[bytes.size - 2].toInt() and 0xFF) shl 8) or
            (bytes[bytes.size - 1].toInt() and 0xFF)

        if (trailerLength !in MIN_TRAILER_SIZE..MAX_TRAILER_SIZE) return null

        val trailerStart = bytes.size - TRAILER_SUFFIX_SIZE - trailerLength
        if (trailerStart < 0) return null

        val mask = MessageDigest.getInstance("SHA-256")
            .digest("$trailerKey:m0:$handle".toByteArray(Charsets.UTF_8))

        val decoded = ByteArray(trailerLength) { i ->
            (bytes[trailerStart + i].toInt() xor mask[i].toInt()).toByte()
        }

        if (
            decoded[0] != 0xAE.toByte() ||
            decoded[1] != 0xDE.toByte() ||
            decoded[2] != 0x58.toByte() ||
            decoded[3] != 0x01.toByte()
        ) {
            return null
        }

        val xorKey = decoded[4].toInt() and 0xFF
        val gutter = decoded[5].toInt() and 0xFF
        val keyLength = decoded[6].toInt() and 0xFF

        if (
            keyLength > MAX_KEY_LENGTH ||
            trailerLength != MIN_TRAILER_SIZE + keyLength ||
            gutter !in 0 until 64
        ) {
            return null
        }

        val key = decoded.copyOfRange(7, 7 + keyLength)

        if (key.any { (it.toInt() and 0xFF) !in 0x20..0x7E }) return null

        return PageTrailer(
            cleanLen = trailerStart,
            key = key,
            xorKey = xorKey,
            gutter = gutter,
        )
    }

    private fun responseWithBytes(response: Response, bytes: ByteArray, contentType: MediaType?): Response {
        val buffer = Buffer().write(bytes)
        return response.newBuilder()
            .body(buffer.asResponseBody(contentType, buffer.size))
            .build()
    }

    private fun isImageHeader(header: ByteArray): Boolean {
        if (header.size >= 12) {
            if (
                header[0] == 'R'.code.toByte() &&
                header[1] == 'I'.code.toByte() &&
                header[2] == 'F'.code.toByte() &&
                header[3] == 'F'.code.toByte() &&
                header[8] == 'W'.code.toByte() &&
                header[9] == 'E'.code.toByte() &&
                header[10] == 'B'.code.toByte() &&
                header[11] == 'P'.code.toByte()
            ) {
                return true
            }
        }

        if (
            header.size >= 8 &&
            header[0] == 0x89.toByte() &&
            header[1] == 'P'.code.toByte() &&
            header[2] == 'N'.code.toByte() &&
            header[3] == 'G'.code.toByte() &&
            header[4] == 0x0D.toByte() &&
            header[5] == 0x0A.toByte() &&
            header[6] == 0x1A.toByte() &&
            header[7] == 0x0A.toByte()
        ) {
            return true
        }

        return header.size >= 3 &&
            header[0] == 0xFF.toByte() &&
            header[1] == 0xD8.toByte() &&
            header[2] == 0xFF.toByte()
    }

    private fun ByteArray.xor(key: Int): ByteArray = ByteArray(size) { i ->
        (this[i].toInt() xor key).toByte()
    }

    private fun proceedPage(chain: Interceptor.Chain, request: Request, keys: VisitKeys): Response {
        val signer = keys.signer
        val (proofName, proof) = signer.proof("p", request.url.pathSegments[2], keys.now())
        val live = liveToken(chain, request, keys)

        val builder = request.newBuilder()
            .url(request.url.newBuilder().fragment(null).build())
            .header(signer.buildName, signer.buildId)
            .header(proofName, proof)

        if (live != null) {
            builder.header(signer.liveName, live)
        }

        val response = chain.proceed(builder.build())
        if (response.code == 409) {
            response.close()
            throw OutdatedVisitException()
        }
        return response
    }

    // The site's heartbeat: pages are only served along a live token, which it hands out for a while
    private fun liveToken(chain: Interceptor.Chain, request: Request, keys: VisitKeys): String? {
        fun cached() = liveTokens[keys.liveKey]
            ?.takeIf { it.expiresAt > Clock.System.now().toEpochMilliseconds() }
            ?.token

        cached()?.let { return it }

        synchronized(liveTokens) {
            cached()?.let { return it }

            val signer = keys.signer
            val (proofName, proof) = signer.proof("v", keys.liveKey, keys.now())
            val live = chain.proceed(
                request.newBuilder()
                    .url(
                        request.url.newBuilder()
                            .encodedPath("/lector/${signer.livePath}/")
                            .query(null)
                            .fragment(null)
                            .build(),
                    )
                    .post(LiveRequest(keys.liveKey).toJsonRequestBody())
                    .header(signer.buildName, signer.buildId)
                    .header(proofName, proof)
                    .build(),
            ).use { response ->
                when {
                    response.code == 409 -> throw OutdatedVisitException()
                    !response.isSuccessful -> null
                    else -> runCatching { response.parseAs<LiveTokenDto>() }.getOrNull()
                }
            } ?: return null

            // Renewed a little before it runs out
            val expiresAt = Clock.System.now().toEpochMilliseconds() + maxOf(MIN_LIVE_TTL, live.ttl - LIVE_MARGIN)
            liveTokens[keys.liveKey] = LiveToken(live.token, expiresAt)
            return live.token
        }
    }

    private fun retryRequest(request: Request, attempt: Int): Request {
        if (attempt < 2) return request
        return request.newBuilder()
            .url(request.url.newBuilder().setQueryParameter("q", "sq").build())
            .build()
    }

    private fun retryDelay(attempt: Int) {
        val delay = when (attempt) {
            1 -> 1_000L
            2 -> 1_500L
            3 -> 2_250L
            else -> 4_000L
        }
        try {
            Thread.sleep(delay)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("Page request interrupted", e)
        }
    }

    private fun VisitKeys.now() = Clock.System.now().toEpochMilliseconds() + clockOffset

    private class LiveToken(val token: String, val expiresAt: Long)

    private class OutdatedVisitException : IOException("The site's reader changed, open the chapter again")

    private class PageTrailer(
        val cleanLen: Int,
        val key: ByteArray,
        val xorKey: Int,
        val gutter: Int,
    )

    companion object {
        private const val LEGACY_XOR_KEY = 0x43
        private const val HEADER_SIZE = 12
        private const val TRAILER_SUFFIX_SIZE = 2
        private const val MIN_TRAILER_SIZE = 7
        private const val MAX_TRAILER_SIZE = 23
        private const val MAX_KEY_LENGTH = 16
        private const val MIN_LIVE_TTL = 5_000L
        private const val LIVE_MARGIN = 5_000L
        private const val MAX_ATTEMPTS = 5
        private const val MIN_IMAGE_SIZE = 200
        private val MEDIA_TYPE = "image/jpeg".toMediaType()
    }
}
