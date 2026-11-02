
package eu.kanade.tachiyomi.extension.es.mhscans

import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.MangasPage
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.online.HttpSource
import eu.kanade.tachiyomi.util.asJsoup
import keiyoushi.utils.firstInstanceOrNull
import keiyoushi.utils.setUrlWithoutDomain
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Request
import okhttp3.Response
import org.jsoup.nodes.Document
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit
import rx.Observable
import rx.schedulers.Schedulers

class MHScans : HttpSource() {

    override val name = "MHScans"
    override val lang = "es"
    override val baseUrl = "https://mhscans.com"
    override val supportsLatest = true
    override val client = network.client

    override fun popularMangaRequest(page: Int): Request = catalogRequest(page, "views")

    override fun popularMangaParse(response: Response): MangasPage = parseMangaList(response)

    override fun latestUpdatesRequest(page: Int): Request = catalogRequest(page, "updated")

    override fun latestUpdatesParse(response: Response): MangasPage = parseMangaList(response)

    override fun searchMangaRequest(
        page: Int,
        query: String,
        filters: FilterList,
    ): Request {
        val libraryUrl = "$baseUrl/library".toHttpUrl().newBuilder().apply {
            if (query.isNotBlank()) addQueryParameter("q", query)
            filters.firstInstanceOrNull<GenreFilter>()
                ?.state
                ?.takeIf(String::isNotBlank)
                ?.let { addQueryParameter("genre", it) }
            filters.firstInstanceOrNull<TypeFilter>()
                ?.selected
                ?.takeIf(String::isNotEmpty)
                ?.let { addQueryParameter("type", it) }
            filters.firstInstanceOrNull<StatusFilter>()
                ?.selected
                ?.takeIf(String::isNotEmpty)
                ?.let { addQueryParameter("status", it) }
            filters.firstInstanceOrNull<SortFilter>()
                ?.selected
                ?.takeIf(String::isNotEmpty)
                ?.let { addQueryParameter("sort", it) }
            addQueryParameter("page", page.toString())
        }.build()

        return GET(libraryUrl, headers)
    }

    override fun searchMangaParse(response: Response): MangasPage = parseMangaList(response)

    private fun catalogRequest(page: Int, sort: String): Request {
        val url = "$baseUrl/library".toHttpUrl().newBuilder()
            .addQueryParameter("sort", sort)
            .addQueryParameter("page", page.toString())
            .build()

        return GET(url, headers)
    }

    private fun parseMangaList(response: Response): MangasPage {
        val document = response.asJsoup()

        val mangas = document.select("div.lib-grid > a[href^=/comics/]")
            // novel chapters are text without images, so they always end up as "No pages found"
            .filterNot { it.selectFirst("div.comic-cover ~ span")?.text() == "Novel" }
            .map { element ->
                SManga.create().apply {
                    setUrlWithoutDomain(element.absUrl("href"))
                    title = element.selectFirst("p")!!.text()
                    thumbnail_url = element.selectFirst("img")?.absUrl("src")
                }
            }
        val hasNextPage = document.selectFirst("nav.lib-pagination a[aria-label=Siguiente]") != null
        return MangasPage(mangas, hasNextPage)
    }

    override fun mangaDetailsParse(response: Response): SManga {
        val document = response.asJsoup()

        return SManga.create().apply {
            setUrlWithoutDomain(response.request.url.toString())
            title = document.selectFirst(".comic-hero h1")!!.text()
            thumbnail_url = document.selectFirst(".comic-hero__cover img")?.absUrl("src")
            description = document.selectFirst("#comic-description")?.text()
            genre = document.select(".comic-chips li").joinToString { it.text() }
            status = when (document.selectFirst(".comic-meta__status")?.text()?.lowercase()) {
                "en emisión" -> SManga.ONGOING
                "completado" -> SManga.COMPLETED
                "en hiato" -> SManga.ON_HIATUS
                "cancelado", "cancelled" -> SManga.CANCELLED
                else -> SManga.UNKNOWN
            }
            initialized = true
        }
    }

    override fun chapterListRequest(manga: SManga): Request =
        GET("$baseUrl${manga.url}/chapters?page=1", headers)

    private fun chapterPageRequest(manga: SManga, page: Int): Request =
        GET("$baseUrl${manga.url}/chapters?page=$page", headers)

    override fun chapterListParse(response: Response): List<SChapter> =
        parseChapters(response.asJsoup())

    override fun fetchChapterList(manga: SManga): Observable<List<SChapter>> =
        Observable.fromCallable {
            val response = client.newCall(chapterListRequest(manga)).execute()
            val totalPages = response.header("X-Pages")?.toIntOrNull() ?: 1
            val firstPage = response.use { parseChapters(it.asJsoup()) }

            firstPage + (2..totalPages).flatMap { page ->
                client.newCall(chapterPageRequest(manga, page)).execute().use {
                    parseChapters(it.asJsoup())
                }
            }
        }.subscribeOn(Schedulers.io())

    // paid chapters link to /auth/login without a chapter id until they're bought
    private fun parseChapters(document: Document): List<SChapter> = document.select("a[href^=/leer/][data-chapter-num]").map { element ->
        SChapter.create().apply {
            setUrlWithoutDomain(element.absUrl("href"))
            name = element.selectFirst("[data-cl-title]")!!.text()
            element.attr("data-chapter-num").toFloatOrNull()?.let { chapter_number = it }
            date_upload = element.selectFirst("[data-cl-title] + div > span")?.text().parseRelativeDate()
        }
    }

    override fun pageListParse(response: Response): List<Page> = response.asJsoup()
        .select("img.page-img")
        .mapIndexed { index, img -> Page(index, imageUrl = img.attr("abs:data-src").ifEmpty { img.absUrl("src") }) }

    override fun imageUrlParse(response: Response): String = throw UnsupportedOperationException()

    override fun getFilterList(): FilterList = FilterList(
        SortFilter("views"),
        TypeFilter(),
        StatusFilter(),
        GenreFilter(),
    )

    private fun String?.parseRelativeDate(): Long {
        val (amount, unit) = this?.lowercase()?.let(RELATIVE_DATE::find)?.destructured ?: return 0L
        val chronoUnit = when {
            unit.startsWith("min") -> ChronoUnit.MINUTES
            unit.startsWith("h") -> ChronoUnit.HOURS
            unit.startsWith("d") -> ChronoUnit.DAYS
            unit.startsWith("sem") -> ChronoUnit.WEEKS
            unit.startsWith("mes") -> ChronoUnit.MONTHS
            unit.startsWith("a") -> ChronoUnit.YEARS
            else -> return 0L
        }
        return ZonedDateTime.now().minus(amount.toLong(), chronoUnit).toInstant().toEpochMilli()
    }

    companion object {
        private val RELATIVE_DATE = Regex("""hace (\d+) (\p{L}+)""")
    }
}
