package eu.kanade.tachiyomi.extension.es.leercapitulo

import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.source.model.Filter
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.MangasPage
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.online.HttpSource
import eu.kanade.tachiyomi.util.asJsoup
import keiyoushi.utils.firstInstanceOrNull
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Request
import okhttp3.Response
import org.jsoup.nodes.Document
import java.text.SimpleDateFormat
import java.util.Locale

class LeerCapitulo : HttpSource() {

    override val name = "LeerCapitulo"
    override val lang = "es"
    override val supportsLatest = true
    override val baseUrl = "https://www.leercapitulo.co"
    override val client = network.client

    override fun headersBuilder() = super.headersBuilder()
        .add("Referer", "$baseUrl/")

    override fun popularMangaRequest(page: Int): Request = catalogRequest(page)

    override fun popularMangaParse(response: Response): MangasPage = parseMangaList(response)

    override fun latestUpdatesRequest(page: Int): Request = GET(
        baseUrl.toHttpUrl().newBuilder()
            .addQueryParameter("page", page.toString())
            .build(),
        headers,
    )

    override fun latestUpdatesParse(response: Response): MangasPage {
        val document = response.asJsoup()

        val mangas = document.select("article.lc-release").mapNotNull { element ->
            val titleLink = element.selectFirst("a.lc-release-title")
                ?: return@mapNotNull null

            val url = titleLink.attr("abs:href")
                .takeIf { it.isNotEmpty() }
                ?: return@mapNotNull null

            SManga.create().apply {
                setUrlWithoutDomain(url)
                title = titleLink.text()
                thumbnail_url = element
                    .selectFirst("a.lc-release-cover img")
                    ?.attr("abs:src")
            }
        }

        val hasNextPage = document.selectFirst(
            "a[rel=next], a[aria-label=Siguiente][href]",
        ) != null

        return MangasPage(mangas, hasNextPage)
    }

    private fun catalogRequest(page: Int): Request {
        val url = baseUrl.toHttpUrl().newBuilder()
            .addPathSegment("manga")
            .addPathSegment("")
            .addQueryParameter("page", page.toString())
            .build()

        return GET(url, headers)
    }

    override fun searchMangaRequest(
        page: Int,
        query: String,
        filters: FilterList,
    ): Request {
        val urlBuilder = baseUrl.toHttpUrl().newBuilder()
            .addPathSegment("manga")
            .addPathSegment("")

        if (query.isNotBlank()) {
            urlBuilder.addQueryParameter("q", query)
        }

        filters.firstInstanceOrNull<GenreFilter>()
            ?.takeIf { it.state != 0 }
            ?.toUriPart()
            ?.takeIf { it.isNotEmpty() }
            ?.let { genre ->
                urlBuilder.addQueryParameter("genre", genre)
            }

        filters.firstInstanceOrNull<ThemeFilter>()
            ?.takeIf { it.state != 0 }
            ?.toUriPart()
            ?.takeIf { it.isNotEmpty() }
            ?.let { theme ->
                urlBuilder.addQueryParameter("theme", theme)
            }

        filters.firstInstanceOrNull<TypeFilter>()
            ?.takeIf { it.state != 0 }
            ?.toUriPart()
            ?.takeIf { it.isNotEmpty() }
            ?.let { type ->
                urlBuilder.addQueryParameter("type", type)
            }

        filters.firstInstanceOrNull<StatusFilter>()
            ?.takeIf { it.state != 0 }
            ?.toUriPart()
            ?.takeIf { it.isNotEmpty() }
            ?.let { status ->
                urlBuilder.addQueryParameter("status", status)
            }

        filters.firstInstanceOrNull<SortFilter>()
            ?.toUriPart()
            ?.takeIf { it.isNotEmpty() }
            ?.let { sort ->
                urlBuilder.addQueryParameter("sort", sort)
            }

        urlBuilder.addQueryParameter("page", page.toString())

        return GET(urlBuilder.build(), headers)
    }

    override fun searchMangaParse(response: Response): MangasPage = parseMangaList(response)

    private fun parseMangaList(response: Response): MangasPage {
        val document = response.asJsoup()

        val mangas = document.select("article.lc-card").mapNotNull { element ->
            val titleLink = element.selectFirst("a.lc-card-name")
                ?: return@mapNotNull null

            val url = titleLink.attr("abs:href")
                .takeIf { it.isNotEmpty() }
                ?: return@mapNotNull null

            SManga.create().apply {
                setUrlWithoutDomain(url)
                title = titleLink.text()
                thumbnail_url = element
                    .selectFirst("a.lc-card-cover img")
                    ?.attr("abs:src")
            }
        }

        val hasNextPage = document.selectFirst(
            "a[rel=next], a[aria-label=Siguiente][href]",
        ) != null

        return MangasPage(mangas, hasNextPage)
    }

    override fun getFilterList(): FilterList = FilterList(
        Filter.Header("Los filtros pueden combinarse entre sí."),
        Filter.Header("La búsqueda utiliza el título, nombre alternativo o autor."),
        GenreFilter(),
        ThemeFilter(),
        TypeFilter(),
        StatusFilter(),
        SortFilter(),
    )

    override fun mangaDetailsParse(response: Response): SManga {
        val document = response.asJsoup()

        val synopsis = document
            .selectFirst("#sinopsis p")
            ?.text()
            ?.takeIf { it.isNotBlank() }

        val altNames = document
            .selectFirst("h1.h3 + p.small.lc-muted")
            ?.text()
            ?.takeIf { it.isNotBlank() }

        val description = buildString {
            if (!synopsis.isNullOrBlank()) {
                append(synopsis)
            }

            if (!altNames.isNullOrBlank()) {
                if (isNotEmpty()) {
                    append("\n\n")
                }
                append("Alt name(s): ")
                append(altNames)
            }
        }.takeIf { it.isNotBlank() }

        return SManga.create().apply {
            title = document
                .selectFirst("h1.h3")
                ?.text()
                ?: document.selectFirst("h1")?.text()
                ?: ""

            thumbnail_url = document
                .selectFirst(".lc-cover-lg img")
                ?.attr("abs:src")

            genre = document
                .select("a.badge.text-bg-secondary.text-decoration-none")
                .joinToString { it.text() }
                .takeIf { it.isNotBlank() }

            author = document.factValue("Autor")
            artist = document.factValue("Dibujo")
            status = document.factValue("Estado")
                ?.toStatus()
                ?: SManga.UNKNOWN

            this.description = description
        }
    }

    override fun chapterListParse(response: Response): List<SChapter> {
        val document = response.asJsoup()

        return document.select("#chapterList a.lc-chapter-row").map { element ->
            SChapter.create().apply {
                setUrlWithoutDomain(element.attr("abs:href"))
                name = element.selectFirst(".n")?.text()
                    ?: element.text()
                date_upload = element
                    .selectFirst(".d")
                    ?.text()
                    ?.toDate()
                    ?: 0L
            }
        }
    }

    override fun pageListParse(response: Response): List<Page> {
        val document = response.asJsoup()

        return document
            .select("#lcPages img[data-src]")
            .sortedBy { it.attr("data-index").toIntOrNull() ?: Int.MAX_VALUE }
            .mapIndexed { index, element ->
                Page(
                    index = index,
                    imageUrl = element.attr("abs:data-src"),
                )
            }
    }

    override fun imageUrlParse(response: Response): String = throw UnsupportedOperationException()

    private fun Document.factValue(label: String): String? = select(".lc-facts li")
        .firstOrNull {
            it.selectFirst(".k")?.text()?.trim() == label
        }
        ?.text()
        ?.removePrefix(label)
        ?.trim()
        ?.takeIf { it.isNotEmpty() }

    private fun String.toDate(): Long = runCatching {
        SimpleDateFormat("yyyy-MM-dd", Locale.US)
            .parse(this)
            ?.time
            ?: 0L
    }.getOrDefault(0L)

    private fun String.toStatus(): Int = when (lowercase(Locale.US)) {
        "ongoing" -> SManga.ONGOING
        "completed" -> SManga.COMPLETED
        "paused" -> SManga.ON_HIATUS
        "cancelled" -> SManga.CANCELLED
        else -> SManga.UNKNOWN
    }
}
