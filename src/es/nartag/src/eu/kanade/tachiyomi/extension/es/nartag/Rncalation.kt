
package eu.kanade.tachiyomi.extension.es.nartag

import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.MangasPage
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.online.HttpSource
import eu.kanade.tachiyomi.util.asJsoup
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Request
import okhttp3.Response
import rx.Observable

class Rncalation : HttpSource() {

    override val name = "Rncalation"
    override val lang = "es"
    override val baseUrl = "https://rncalation.online"
    override val supportsLatest = true
    override val client = network.client

    override fun headersBuilder() = super.headersBuilder().add("Referer", "$baseUrl/")

    override fun popularMangaRequest(page: Int): Request = GET("$baseUrl/library?sort=views&page=$page", headers)

    override fun popularMangaParse(response: Response): MangasPage {
        val document = response.asJsoup()
        val mangas = document.select(".lib-grid a.comic-card").mapNotNull { element ->
            val type = element.selectFirst("span.absolute.top-2.left-2")?.text()
            if (type != null && type.contains("Novel", ignoreCase = true)) {
                return@mapNotNull null
            }
            SManga.create().apply {
                url = element.absUrl("href").toHttpUrl().encodedPath
                title = element.selectFirst("p.leading-snug")!!.text()
                thumbnail_url = element.selectFirst("img")?.attr("abs:src")
            }
        }
        val hasNextPage = document.selectFirst("a.page-btn--nav:not(.page-btn--disabled)[href]") != null
        return MangasPage(mangas, hasNextPage)
    }

    override fun latestUpdatesRequest(page: Int): Request = GET("$baseUrl/library?sort=updated&page=$page", headers)

    override fun latestUpdatesParse(response: Response): MangasPage = popularMangaParse(response)

    override fun searchMangaRequest(page: Int, query: String, filters: FilterList): Request {
        val url = "$baseUrl/library".toHttpUrl().newBuilder().apply {
            addQueryParameter("page", page.toString())
            if (query.isNotEmpty()) addQueryParameter("q", query)
            filters.forEach { filter ->
                when (filter) {
                    is SortFilter -> addQueryParameter("sort", sortOptions[filter.state].value)
                    is TypeFilter -> if (filter.state > 0) addQueryParameter("type", filter.values[filter.state])
                    is StatusFilter -> if (filter.state > 0) addQueryParameter("status", filter.values[filter.state])
                    is GenreFilter -> if (filter.state > 0) addQueryParameter("genre", filter.values[filter.state])
                    else -> {}
                }
            }
        }.build()
        return GET(url, headers)
    }

    override fun searchMangaParse(response: Response): MangasPage = popularMangaParse(response)

    override fun mangaDetailsParse(response: Response): SManga {
        val document = response.asJsoup()
        return SManga.create().apply {
            description = document.selectFirst("p#comic-description")?.text() ?: ""

            val badges = document.select("span.inline-flex.items-center.rounded")
                .map { it.text().trim() }

            status = when {
                badges.any {
                    it.equals("En emisión", ignoreCase = true) ||
                        it.equals("Emisión", ignoreCase = true) ||
                        it.equals("En curso", ignoreCase = true) ||
                        it.equals("Ongoing", ignoreCase = true)
                } -> SManga.ONGOING
                badges.any {
                    it.equals("Completado", ignoreCase = true) ||
                        it.equals("Completed", ignoreCase = true)
                } -> SManga.COMPLETED
                badges.any {
                    it.equals("En pausa", ignoreCase = true) ||
                        it.equals("Pausa", ignoreCase = true) ||
                        it.equals("Hiatus", ignoreCase = true)
                } -> SManga.ON_HIATUS
                badges.any {
                    it.equals("Cancelado", ignoreCase = true) ||
                        it.equals("Cancelled", ignoreCase = true)
                } -> SManga.CANCELLED
                else -> SManga.UNKNOWN
            }

            val excludedBadges = listOf(
                "emisión",
                "en emisión",
                "en curso",
                "ongoing",
                "completado",
                "completed",
                "pausa",
                "en pausa",
                "hiatus",
                "cancelado",
                "cancelled",
            )

            genre = badges
                .filter { it.lowercase() !in excludedBadges }
                .distinct()
                .joinToString(", ")

            val groupName = document.selectFirst("a[href^='/groups/']")?.text()
            if (!groupName.isNullOrEmpty()) {
                author = groupName
                artist = groupName
            }

            document.select(".flex.items-baseline.justify-between.gap-2").forEach { row ->
                val label = row.selectFirst("span.text-\\[var\\(--color-text3\\)\\]")?.text()
                val value = row.selectFirst("span.text-\\[var\\(--color-text2\\)\\]")?.text()
                if (label == "Autor") author = value
                if (label == "Arte") artist = value
            }
        }
    }

    override fun fetchChapterList(manga: SManga): Observable<List<SChapter>> = Observable.fromCallable {
        val slug = manga.url.removeSuffix("/").substringAfterLast("/")
        val allChapters = mutableListOf<SChapter>()
        var page = 1
        var hasNextPage: Boolean
        do {
            val chapters = client.newCall(chapterListRequest(slug, page)).execute().use { response ->
                val parsed = chapterListParse(response)
                val currentPage = response.header("x-page")?.toIntOrNull() ?: page
                val totalPages = response.header("x-pages")?.toIntOrNull() ?: currentPage
                hasNextPage = currentPage < totalPages
                parsed
            }
            if (chapters.isEmpty()) break
            allChapters.addAll(chapters)
            page++
        } while (hasNextPage)
        allChapters
    }

    private fun chapterListRequest(slug: String, page: Int) = GET("$baseUrl/comics/$slug/chapters?page=$page", headers)

    override fun chapterListParse(response: Response): List<SChapter> {
        val document = response.asJsoup()

        android.util.Log.d(
            "Rncalation",
            "HTML: ${document.body().html().take(12000)}",
        )

        val groups = document.select("div[data-chapter-group]")
        val links = document.select("a[data-chapter-id]")
        val versions = document.select("div[data-chgroup-version-row]")

        android.util.Log.d(
            "Rncalation",
            "Groups: ${groups.size}, Versions: ${versions.size}, Links: ${links.size}",
        )

        groups.forEach { group ->
            android.util.Log.d(
                "Rncalation",
                "Chapter ${group.attr("data-chapter-num")}: " +
                    "versions=${group.select("div[data-chgroup-version-row]").size}, " +
                    "links=${group.select("a[data-chapter-id]").size}",
            )
        }

        return groups.flatMap { group ->
            val chapterNumber = group.attr("data-chapter-num").toFloatOrNull() ?: 0f
            val chapterName = group.attr("data-chapter-label").ifEmpty {
                "Capítulo ${chapterNumber.toInt()}"
            }

            group.select("a[data-chapter-id]").mapNotNull { link ->
                val version = link.parents().firstOrNull {
                    it.hasAttr("data-chgroup-version-row")
                } ?: return@mapNotNull null

                val groupName = version.selectFirst("[data-cl-group]")?.text()?.trim()
                val timestamp = version.selectFirst("[data-ts]")?.attr("data-ts")

                SChapter.create().apply {
                    url = link.absUrl("href").toHttpUrl().encodedPath
                    name = if (!groupName.isNullOrEmpty()) {
                        "$chapterName - $groupName"
                    } else {
                        chapterName
                    }
                    chapter_number = chapterNumber
                    date_upload = timestamp?.let {
                        runCatching { java.time.Instant.parse(it).toEpochMilli() }.getOrNull()
                    } ?: 0L
                }
            }
        }
    }

    override fun pageListParse(response: Response): List<Page> {
        val document = response.asJsoup()
        return document.select("img.page-img, .page-wrap img").mapIndexed { index, element ->
            val imageUrl = element.attr("abs:data-src").ifEmpty { element.attr("abs:src") }
            Page(index, imageUrl = imageUrl)
        }
    }

    override fun imageUrlParse(response: Response): String = throw UnsupportedOperationException()

    override fun getFilterList(): FilterList = FilterList(
        SortFilter(),
        TypeFilter(),
        StatusFilter(),
        GenreFilter(genresList),
    )
}
