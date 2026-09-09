package eu.kanade.tachiyomi.extension.es.jeazscans

import android.util.Base64
import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.source.model.Filter
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
    override fun popularMangaRequest(page: Int): Request = directoryRequest(
        page = page,
        query = null,
        filters = FilterList(),
    )

    override fun popularMangaParse(response: Response): MangasPage = parseDirectory(response)

    override fun latestUpdatesRequest(page: Int): Request = directoryRequest(
        page = page,
        query = null,
        filters = FilterList(
            OrderFilter().apply {
                state = 0
            },
        ),
    )

    override fun latestUpdatesParse(response: Response): MangasPage = parseDirectory(response)

    override fun getFilterList(): FilterList = FilterList(
        TypeFilter(),
        StatusFilter(),
        OrderFilter(),
        GenreFilter(),
    )

    private fun directoryRequest(
        page: Int,
        query: String?,
        filters: FilterList,
    ): Request {
        val url = "$baseUrl/directorio.php"
            .toHttpUrl()
            .newBuilder()
            .addQueryParameter("page", page.toString())

        query
            ?.takeIf { it.isNotBlank() }
            ?.let {
                url.addQueryParameter("q", it.trim())
            }

        val type = filters
            .filterIsInstance<TypeFilter>()
            .firstOrNull()

        if (type != null && type.state > 0) {
            url.addQueryParameter(
                "tipo",
                type.values[type.state],
            )
        }

        val status = filters
            .filterIsInstance<StatusFilter>()
            .firstOrNull()

        if (status != null && status.state > 0) {
            url.addQueryParameter(
                "estado",
                status.values[status.state],
            )
        }

        val order = filters
            .filterIsInstance<OrderFilter>()
            .firstOrNull()

        if (order != null) {
            url.addQueryParameter(
                "orden",
                order.values[order.state],
            )
        } else {
            url.addQueryParameter(
                "orden",
                "actualizado",
            )
        }

        val genres = filters
            .filterIsInstance<GenreFilter>()
            .firstOrNull()

        genres?.state
            ?.filter { it.state }
            ?.forEach { checkbox ->
                url.addQueryParameter(
                    "generos[]",
                    checkbox.name,
                )
            }

        return GET(
            url.build(),
            headers,
        )
    }

    private fun parseDirectory(response: Response): MangasPage {
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
                    ?: return@mapNotNull null

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
                    .equals(
                        "Página siguiente",
                        ignoreCase = true,
                    )
            }

        return MangasPage(
            mangas,
            hasNextPage,
        )
    }

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

    override fun imageRequest(page: Page): Request = GET(
        page.imageUrl!!,
        headers.newBuilder()
            .set("Referer", currentChapterUrl)
            .set(
                "Accept",
                "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
            )
            .build(),
    )

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

    override fun imageUrlParse(response: Response): String = throw UnsupportedOperationException()

    private class TypeFilter :
        Filter.Select<String>(
            "Tipo de proyecto",
            arrayOf(
                "Todos",
                "manhua",
                "manhwa",
                "manga",
                "novela",
            ),
        )

    private class StatusFilter :
        Filter.Select<String>(
            "Estado del proyecto",
            arrayOf(
                "Todos",
                "emision",
                "finalizado",
                "pausado",
                "hiatus",
            ),
        )

    private class OrderFilter :
        Filter.Select<String>(
            "Ordenar por",
            arrayOf(
                "actualizado",
                "vistas",
                "votos",
                "nuevo",
                "viejo",
                "az",
                "za",
            ),
        )

    private class GenreFilter :
        Filter.Group<Filter.CheckBox>(
            "Géneros",
            listOf(
                Filter.CheckBox("Acción"),
                Filter.CheckBox("Artes marciales"),
                Filter.CheckBox("Aventura"),
                Filter.CheckBox("Cazadores"),
                Filter.CheckBox("Ciencia Ficción"),
                Filter.CheckBox("Comedia"),
                Filter.CheckBox("Crimen"),
                Filter.CheckBox("cultivacion"),
                Filter.CheckBox("Cultivo"),
                Filter.CheckBox("Demonios"),
                Filter.CheckBox("Deportes"),
                Filter.CheckBox("Drama"),
                Filter.CheckBox("Ecchi"),
                Filter.CheckBox("Escolar"),
                Filter.CheckBox("Familia"),
                Filter.CheckBox("Fantasía"),
                Filter.CheckBox("Gore"),
                Filter.CheckBox("Harem"),
                Filter.CheckBox("harén"),
                Filter.CheckBox("Histórico"),
                Filter.CheckBox("Isekai"),
                Filter.CheckBox("Josei"),
                Filter.CheckBox("Magia"),
                Filter.CheckBox("Manga"),
                Filter.CheckBox("Manhua"),
                Filter.CheckBox("Manhwa"),
                Filter.CheckBox("Mecha"),
                Filter.CheckBox("Militar"),
                Filter.CheckBox("Misterio"),
                Filter.CheckBox("Murim"),
                Filter.CheckBox("Policiaco"),
                Filter.CheckBox("Post-Apocalíptico"),
                Filter.CheckBox("Psicológico"),
                Filter.CheckBox("Realidad Virtual"),
                Filter.CheckBox("Recuentos de la vida"),
                Filter.CheckBox("Reencarnación"),
                Filter.CheckBox("Regresión"),
                Filter.CheckBox("Romance"),
                Filter.CheckBox("Seinen"),
                Filter.CheckBox("Shonen"),
                Filter.CheckBox("Shoujo"),
                Filter.CheckBox("Sistemas"),
                Filter.CheckBox("Sobrenatural"),
                Filter.CheckBox("Superpoderes"),
                Filter.CheckBox("Supervivencia"),
                Filter.CheckBox("Terror"),
                Filter.CheckBox("Torre"),
                Filter.CheckBox("Tragedia"),
                Filter.CheckBox("Transmigración"),
                Filter.CheckBox("Vampiros"),
                Filter.CheckBox("Venganza"),
                Filter.CheckBox("Viaje en el tiempo"),
                Filter.CheckBox("Videojuegos"),
                Filter.CheckBox("Wuxia"),
                Filter.CheckBox("Xianxia"),
                Filter.CheckBox("Xuanhuan"),
                Filter.CheckBox("Zombies"),
            ),
        )

    companion object {
        private val SINOPSIS_REGEX = Regex("^SINOPSIS:?\\s*", RegexOption.IGNORE_CASE)
        private val NUMBER_REGEX = Regex("""\d+""")
        private val PATH_SLUG_CAP_REGEX = Regex("/leer/([^/]+)/capitulo-([0-9.]+)", RegexOption.IGNORE_CASE)
        private val MANGA_SLUG_REGEX = Regex("""MANGA_SLUG\s*=\s*["']([^"']+)["']""")
        private val CAP_INICIAL_REGEX = Regex("""CAP_INICIAL\s*=\s*["']([^"']+)["']""")
    }
}
