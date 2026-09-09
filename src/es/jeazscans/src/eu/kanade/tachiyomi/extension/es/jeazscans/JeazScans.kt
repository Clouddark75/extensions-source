package eu.kanade.tachiyomi.extension.es.jeazscans

import android.util.Base64
import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.MangasPage
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.online.HttpSource
import eu.kanade.tachiyomi.util.asJsoup
import keiyoushi.utils.parseAs
import keiyoushi.utils.tryParse
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.jsoup.nodes.Document
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale

class JeazScans : HttpSource() {

    override val name = "Jeaz Scans"

    override val baseUrl = "https://lectorhub.j5z.xyz"

    override val lang = "es"

    override val supportsLatest = true

    override val versionId = 2

    override val client: OkHttpClient = network.client.newBuilder()
        .build()

    private val dateFormat by lazy {
        SimpleDateFormat("dd MMM, yyyy", Locale.US)
    }

    private var currentChapterUrl = baseUrl

    // The site migrated to custom home sections and PHP routes for search.
    override fun popularMangaRequest(page: Int): Request =
        GET(
            "$baseUrl/directorio.php?page=$page",
            headers,
        )

    override fun popularMangaParse(response: Response): MangasPage {
        val document = response.asJsoup()

        val mangas = document
            .select("a.directory-card[href*='manga.php?id=']")
            .mapNotNull { element ->

                val href = element.attr("abs:href")
                if (href.isBlank()) {
                    return@mapNotNull null
                }

                val title = element
                    .selectFirst(".directory-card-title-row h3")
                    ?.text()
                    ?.trim()
                    ?: element
                        .attr("aria-label")
                        .removePrefix("Abrir ")
                        .trim()

                if (title.isBlank()) {
                    return@mapNotNull null
                }

                SManga.create().apply {
                    setUrlWithoutDomain(href)
                    this.title = title

                    thumbnail_url = element
                        .selectFirst(".directory-cover img")
                        ?.attr("abs:src")
                }
            }

        val hasNextPage = document
            .select("nav.directory-pagination a")
            .any { element ->
                element
                    .attr("aria-label")
                    .equals("Página siguiente", ignoreCase = true)
            }

        return MangasPage(
            mangas,
            hasNextPage,
        )
    }

    override fun latestUpdatesRequest(page: Int): Request =
        GET(
            "$baseUrl/directorio.php?page=$page",
            headers,
        )

    override fun latestUpdatesParse(response: Response): MangasPage =
        popularMangaParse(response)

    override fun mangaDetailsParse(response: Response): SManga {
        val document = response.asJsoup()
        return SManga.create().apply {
            title = document.selectFirst("h1.blood-title")!!.text()

            description = buildString {
                val descriptionBlock = document.selectFirst("div.text-gray-200:has(h3:matchesOwn((?i)SINOPSIS))")
                    ?: document.selectFirst("div.text-gray-200")
                descriptionBlock?.let {
                    append(it.ownText().ifEmpty { it.text().replace(SINOPSIS_REGEX, "") })
                }
            }

            thumbnail_url = document.selectFirst("div.lg\\:col-span-3 div.cultivation-panel img")?.attr("abs:src")

            genre = document.select("a[href*='directorio.php?genero=']").joinToString { it.text() }

            val statusText = document.selectFirst("span.status-badge")?.text().orEmpty().lowercase()
            if (statusText.isNotEmpty()) {
                status = when {
                    statusText.contains("complet") -> SManga.COMPLETED
                    arrayOf("pausa", "hiato").any { statusText.contains(it) } -> SManga.ON_HIATUS
                    arrayOf("cancel", "aband").any { statusText.contains(it) } -> SManga.CANCELLED
                    arrayOf("cultivo", "curso", "ongoing", "emision").any { statusText.contains(it) } -> SManga.ONGOING
                    else -> SManga.UNKNOWN
                }
            }
        }
    }

    override fun chapterListParse(response: Response): List<SChapter> {
        val document = response.asJsoup()

        val mangaId = document
            .selectFirst("[data-manga-id]")
            ?.attr("data-manga-id")
            ?.toIntOrNull()
            ?: document
                .location()
                .toHttpUrlOrNull()
                ?.queryParameter("id")
                ?.toIntOrNull()
            ?: return emptyList()

        val chapters = mutableListOf<SChapter>()

        var offset = 0
        val limit = 30

        while (true) {
            val apiUrl = "$baseUrl/api_capitulos_manga.php"
                .toHttpUrl()
                .newBuilder()
                .addQueryParameter("manga_id", mangaId.toString())
                .addQueryParameter("offset", offset.toString())
                .addQueryParameter("limit", limit.toString())
                .addQueryParameter("orden", "desc")
                .build()

            val json = client.newCall(
                GET(
                    apiUrl,
                    headers.newBuilder()
                        .set("Referer", document.location())
                        .build(),
                ),
            ).execute().use { result ->
                if (!result.isSuccessful) {
                    throw Exception("HTTP ${result.code} loading chapters")
                }

                result.body.string()
            }

            val jsonObject = org.json.JSONObject(json)

            if (!jsonObject.optBoolean("success", false)) {
                throw Exception("API returned an error while loading chapters")
            }

            val chapterArray = jsonObject.optJSONArray("chapters")
                ?: break

            if (chapterArray.length() == 0) {
                break
            }

            for (i in 0 until chapterArray.length()) {
                val chapter = chapterArray.getJSONObject(i)

                val id = chapter.optInt("id")
                val number = chapter.optString("number")

                val chapterNumber = number.toFloatOrNull()
                    ?: continue

                val title = chapter
                    .optString("title")
                    .ifBlank {
                        "Chapter ${number.removeSuffix(".0")}"
                    }

                val publishedAt = chapter.optString("published_at")

                chapters += SChapter.create().apply {
                    setUrlWithoutDomain(
                        "$baseUrl/ver_capitulo.php?id=$id",
                    )

                    chapter_number = chapterNumber
                    name = title
                    date_upload = parseChapterDate(publishedAt)
                }
            }

            val hasMore = jsonObject.optBoolean(
                "has_more",
                false,
            )

            if (!hasMore) {
                break
            }

            val nextOffset = jsonObject.optInt(
                "next_offset",
                offset + limit,
            )

            if (nextOffset <= offset) {
                break
            }

            offset = nextOffset
        }

        return chapters
            .distinctBy { it.url }
            .sortedByDescending { it.chapter_number }
    }

    private fun parseChapterDate(date: String?): Long {
        if (date.isNullOrEmpty()) return 0L
        val lowercaseDate = date.lowercase()
        return when {
            lowercaseDate.contains("hace") -> {
                val number = NUMBER_REGEX.find(lowercaseDate)?.value?.toIntOrNull() ?: return 0L
                val cal = Calendar.getInstance()
                when {
                    lowercaseDate.contains("segundo") -> cal.apply { add(Calendar.SECOND, -number) }.timeInMillis
                    lowercaseDate.contains("minuto") -> cal.apply { add(Calendar.MINUTE, -number) }.timeInMillis
                    lowercaseDate.contains("hora") -> cal.apply { add(Calendar.HOUR, -number) }.timeInMillis
                    lowercaseDate.contains("día") || lowercaseDate.contains("dia") -> cal.apply { add(Calendar.DAY_OF_MONTH, -number) }.timeInMillis
                    lowercaseDate.contains("semana") -> cal.apply { add(Calendar.WEEK_OF_YEAR, -number) }.timeInMillis
                    lowercaseDate.contains("mes") -> cal.apply { add(Calendar.MONTH, -number) }.timeInMillis
                    lowercaseDate.contains("año") -> cal.apply { add(Calendar.YEAR, -number) }.timeInMillis
                    else -> 0L
                }
            }
            lowercaseDate.contains("ayer") -> {
                Calendar.getInstance().apply { add(Calendar.DAY_OF_MONTH, -1) }.timeInMillis
            }
            lowercaseDate.contains("hoy") -> {
                Calendar.getInstance().timeInMillis
            }
            else -> dateFormat.tryParse(date)
        }
    }

    override fun pageListParse(response: Response): List<Page> {
        currentChapterUrl = response.request.url.toString()

        val document = response.asJsoup()

        val imageElements = document.select(
            "img.reader-page-image",
        )

        if (imageElements.isNotEmpty()) {
            return imageElements.mapIndexedNotNull { index, element ->
                val imageUrl = element.attr("abs:data-src")

                if (imageUrl.isNotBlank()) {
                    Page(
                        index = index,
                        imageUrl = imageUrl,
                    )
                } else {
                    null
                }
            }
        }

        return fetchPagesFromApi(document)
    }

    override fun imageRequest(page: Page): Request {
        val request = GET(
            page.imageUrl!!,
            headers.newBuilder()
                .set("Referer", currentChapterUrl)
                .set(
                    "Accept",
                    "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
                )
                .build(),
        )

        return request
    }

    private fun fetchPagesFromApi(document: Document): List<Page> {
        val (slug, cap) = extractSlugAndCap(document) ?: throw Exception("Could not extract slug/cap for API")
        val apiUrl = buildApiUrl(document.location(), slug, cap) ?: throw Exception("Could not build API URL")

        val requestHeaders = headers.newBuilder()
            .set("Referer", document.location())
            .build()

        val payload = client.newCall(GET(apiUrl, requestHeaders)).execute().use { response ->
            if (!response.isSuccessful) {
                throw Exception("HTTP error ${response.code}")
            }

            val apiResponse = response.parseAs<ApiLectorResponse>()
            if (!apiResponse.success) throw Exception("API returned error")

            apiResponse
        }

        val pages = payload.paginas

        return pages.filter { it.dataVerify.isNotBlank() }
            .sortedBy { it.orden }
            .mapNotNull { decodeVerifyToUrl(it.dataVerify) }
            .distinct()
            .mapIndexed { idx, imageUrl -> Page(idx, imageUrl = imageUrl) }
    }

    private fun decodeVerifyToUrl(dataVerify: String): String? {
        val decoded = runCatching {
            String(Base64.decode(dataVerify, Base64.DEFAULT))
        }.getOrNull() ?: return null

        val url = decoded.reversed().trim()
        if (!url.startsWith("http")) return null
        return url
    }

    private fun extractSlugAndCap(document: Document): Pair<String, String>? {
        val locationUrl = document.location().toHttpUrlOrNull()
        val slugFromQuery = locationUrl?.queryParameter("manga")?.trim().orEmpty()
        val capFromQuery = locationUrl?.queryParameter("cap")?.trim().orEmpty()
        if (slugFromQuery.isNotBlank() && capFromQuery.isNotBlank()) {
            return slugFromQuery to capFromQuery
        }

        val fromPath = PATH_SLUG_CAP_REGEX
            .find(document.location())
            ?.groupValues
        if (fromPath != null && fromPath.size >= 3) {
            return fromPath[1] to fromPath[2]
        }

        val scriptContent = document.select("script").joinToString("\n") { it.data() + "\n" + it.html() }
        val slugFromScript = MANGA_SLUG_REGEX
            .find(scriptContent)
            ?.groupValues
            ?.getOrNull(1)
            .orEmpty()
        val capFromScript = CAP_INICIAL_REGEX
            .find(scriptContent)
            ?.groupValues
            ?.getOrNull(1)
            .orEmpty()

        if (slugFromScript.isNotEmpty() && capFromScript.isNotEmpty()) {
            return slugFromScript to capFromScript
        }

        return null
    }

    private fun buildApiUrl(location: String, slug: String, cap: String): String? {
        val current = location.toHttpUrlOrNull() ?: return null

        return runCatching {
            current.newBuilder()
                .encodedPath("/api_lector.php")
                .setQueryParameter("slug", slug)
                .setQueryParameter("cap", cap)
                .build()
                .toString()
        }.getOrNull()
    }

    override fun searchMangaRequest(page: Int, query: String, filters: FilterList): Request = if (query.isBlank()) {
        latestUpdatesRequest(page)
    } else {
        val url = "$baseUrl/ajax_search.php".toHttpUrl().newBuilder()
            .addQueryParameter("q", query.trim())
            .build()
        GET(url, headers)
    }

    override fun searchMangaParse(response: Response): MangasPage {
        if (!response.request.url.encodedPath.endsWith("/ajax_search.php")) {
            return latestUpdatesParse(response)
        }

        val items = response.parseAs<List<SearchResponseItem>>()
        val mangas = items.mapNotNull { it.toSManga(baseUrl) }

        return MangasPage(mangas, false)
    }

    override fun imageUrlParse(response: Response) = throw UnsupportedOperationException()

    companion object {
        private val SINOPSIS_REGEX = Regex("^SINOPSIS:?\\s*", RegexOption.IGNORE_CASE)
        private val CHAPTER_NUMBER_REGEX = Regex("capitulo-([0-9.]+)", RegexOption.IGNORE_CASE)
        private val NUMBER_REGEX = Regex("""\d+""")
        private val PATH_SLUG_CAP_REGEX = Regex("/leer/([^/]+)/capitulo-([0-9.]+)", RegexOption.IGNORE_CASE)
        private val MANGA_SLUG_REGEX = Regex("""MANGA_SLUG\s*=\s*["']([^"']+)["']""")
        private val CAP_INICIAL_REGEX = Regex("""CAP_INICIAL\s*=\s*["']([^"']+)["']""")
    }
}
