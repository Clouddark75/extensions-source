
package eu.kanade.tachiyomi.extension.es.aedex

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import eu.kanade.tachiyomi.multisrc.catharsis.TilePlan
import eu.kanade.tachiyomi.multisrc.catharsis.descramble
import keiyoushi.network.Fetch
import keiyoushi.network.fetch
import keiyoushi.utils.parseAs
import keiyoushi.utils.toJsonRequestBody
import keiyoushi.utils.xor
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.asResponseBody
import okio.Buffer
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.roundToInt
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

        val parts = fragment.split(':', limit = 7)
        val keys = VisitKeys.parse(parts)
        val hasXorByte = parts.size >= 7
        val index = parts[if (hasXorByte) 5 else 4].toInt()
        val chapterKey = parts[if (hasXorByte) 6 else 5]

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

                else -> return processPage(response, currentKeys)
            }
        }
    }

    private fun processPage(response: Response, keys: VisitKeys): Response {
        val pageXorKey = response.header("X-Page-Xor")?.toIntOrNull()
            ?.takeIf { it != 0 }
            ?: keys.xorByte
        val scrambleKey = response.header("X-Page-Key").orEmpty()
        val rawGutter = response.header("X-Tile-Gutter")?.toIntOrNull() ?: 0
        val tileGutter = rawGutter.takeIf { it in 1 until 64 } ?: 0

        val header = response.body.source().peek().readByteArray(HEADER_SIZE)
        var xorKey = if (isImageHeader(header)) {
            0
        } else {
            pageXorKey
        }

        if (xorKey != 0 && !isImageHeader(header.xor(xorKey)) && xorKey != LEGACY_XOR_KEY) {
            xorKey = LEGACY_XOR_KEY
        }

        if (!isImageHeader(header.xor(xorKey))) {
            response.close()
            throw IOException("Unknown page image format")
        }

        val plain = if (xorKey == 0) response else response.xor(xorKey)
        if (scrambleKey.isBlank()) return plain

        val image = plain.body.use { BitmapFactory.decodeStream(it.byteStream()) }
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

        val result = descramble(image, gutter) { width, height ->
            tilePlan(mulberry32(scrambleKey), width, height)
        }
        image.recycle()

        val buffer = Buffer()
        result.compress(Bitmap.CompressFormat.JPEG, 95, buffer.outputStream())
        result.recycle()
        return response.newBuilder()
            .body(buffer.asResponseBody(MEDIA_TYPE, buffer.size))
            .build()
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

    companion object {
        private const val LEGACY_XOR_KEY = 0x43
        private const val HEADER_SIZE = 12L
        private const val MIN_LIVE_TTL = 5_000L
        private const val LIVE_MARGIN = 5_000L
        private const val MAX_ATTEMPTS = 5
        private const val MIN_IMAGE_SIZE = 200
        private val MEDIA_TYPE = "image/jpeg".toMediaType()
    }
}

// The reader's page shuffle generator
private fun mulberry32(seedKey: String): () -> Double {
    var seed = 0
    for (char in seedKey) seed = 31 * seed + char.code
    return {
        var t = (seed + 0x6d2b79f5).also { seed = it }
        t = (t xor (t ushr 15)) * (t or 1)
        t = t xor (t + (t xor (t ushr 7)) * (t or 61))
        t.toUInt().toDouble() / 4294967296.0
    }
}

// The reader's 8x8 plan drawn from [random]
private fun tilePlan(random: () -> Double, width: Int, height: Int): TilePlan {
    val cols = boundaries(random, width)
    val rows = boundaries(random, height)
    return TilePlan(cols, rows, permutation(random), permutation(random))
}

private fun boundaries(random: () -> Double, total: Int): IntArray {
    val bounds = IntArray(GRID + 1)
    bounds[GRID] = total
    val base = total / GRID
    var position = 0
    for (i in 0 until GRID - 1) {
        val max = total - position - (GRID - 1 - i) * MIN_TILE
        position += (base + ((random() * 0.7 - 0.35) * base).roundToInt()).coerceIn(MIN_TILE, maxOf(MIN_TILE, max))
        bounds[i + 1] = position
    }
    return bounds
}

private fun permutation(random: () -> Double): IntArray {
    val order = IntArray(GRID) { it }
    for (i in GRID - 1 downTo 1) {
        val j = (random() * (i + 1)).toInt()
        order[i] = order[j].also { order[j] = order[i] }
    }
    return order
}

private const val GRID = 8
private const val MIN_TILE = 16
