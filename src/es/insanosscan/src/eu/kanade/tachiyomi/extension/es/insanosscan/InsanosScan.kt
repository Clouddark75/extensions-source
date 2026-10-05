package eu.kanade.tachiyomi.extension.es.insanosscan

import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.MangasPage
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.online.HttpSource
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.Request
import okhttp3.Response
import org.jsoup.nodes.Document
import java.time.Instant

class InsanosLibrary : HttpSource() {

    override val name = "Insanos Library"

    override val baseUrl = "https://insanoslibrary.com"

    override val lang = "es"

    override val supportsLatest = true

    private val json = Json {
        ignoreUnknownKeys = true
    }

    override fun popularMangaRequest(page: Int): Request {
        return GET("$baseUrl/series/", headers)
    }

    override fun popularMangaParse(response: Response): MangasPage {
        val series = parseSeries(response)
            .sortedByDescending { it.viewCount }

        return MangasPage(
            mangas = series.map { it.toSManga() },
            hasNextPage = false,
        )
    }

    override fun latestUpdatesRequest(page: Int): Request {
        return GET("$baseUrl/series/", headers)
    }

    override fun latestUpdatesParse(response: Response): MangasPage {
        val series = parseSeries(response)
            .sortedByDescending {
                it.updatedAt ?: it.createdAt ?: ""
            }

        return MangasPage(
            mangas = series.map { it.toSManga() },
            hasNextPage = false,
        )
    }

    override fun searchMangaRequest(
        page: Int,
        query: String,
        filters: FilterList,
    ): Request {
        return GET(
            "$baseUrl/series/",
            headers,
        )
    }

    override fun searchMangaParse(response: Response): MangasPage {
        val series = parseSeries(response)

        return MangasPage(
            mangas = series.map { it.toSManga() },
            hasNextPage = false,
        )
    }

    override fun mangaDetailsRequest(manga: SManga): Request {
        return GET(
            "$baseUrl/series/${manga.url}",
            headers,
        )
    }

    override fun mangaDetailsParse(response: Response): SManga {
        return json.decodeFromString<SeriesDto>(
            response.body!!.string(),
        ).toSManga()
    }

    override fun chapterListRequest(manga: SManga): Request {
        return GET(
            "$baseUrl/series/${manga.url}/chapters",
            headers,
        )
    }

    override fun chapterListParse(response: Response): List<SChapter> {
        return json.decodeFromString<List<ChapterDto>>(
            response.body!!.string(),
        )
            .filter { it.isPublished }
            .sortedByDescending { it.chapterNumber }
            .map { it.toSChapter() }
    }

    override fun pageListRequest(chapter: SChapter): Request {
        return GET(
            "$baseUrl${chapter.url}",
            headers,
        )
    }

    override fun pageListParse(document: Document): List<Page> {
        return document
            .select("figure.page-wrapper[data-page-path]")
            .mapIndexed { index, element ->
                Page(
                    index = index,
                    imageUrl = element.absUrl("data-page-path"),
                )
            }
    }

    private fun parseSeries(response: Response): List<SeriesDto> {
        return json.decodeFromString(response.body!!.string())
    }

    @Serializable
    private data class SeriesDto(
        val id: Int,
        val title: String,
        val description: String? = null,
        @SerialName("cover_image")
        val coverImage: String? = null,
        val genre: String? = null,
        @SerialName("series_type")
        val seriesType: String? = null,
        @SerialName("alt_title")
        val altTitle: String? = null,
        val author: String? = null,
        @SerialName("reading_direction")
        val readingDirection: String? = null,
        val status: String? = null,
        @SerialName("age_rating")
        val ageRating: String? = null,
        @SerialName("chapter_count")
        val chapterCount: Int = 0,
        @SerialName("view_count")
        val viewCount: Int = 0,
        @SerialName("rating_average")
        val ratingAverage: Double = 0.0,
        @SerialName("rating_count")
        val ratingCount: Int = 0,
        @SerialName("created_at")
        val createdAt: String? = null,
        @SerialName("updated_at")
        val updatedAt: String? = null,
    ) {

        fun toSManga(): SManga {
            return SManga.create().apply {
                url = id.toString()

                title = this@SeriesDto.title

                author = this@SeriesDto.author

                description = this@SeriesDto.description.orEmpty()

                thumbnail_url = coverImage
                    ?.takeIf { it.isNotBlank() }
                    ?.let {
                        if (it.startsWith("http")) {
                            it
                        } else {
                            "$baseUrl$it"
                        }
                    }

                genre = buildList {
                    this@SeriesDto.genre
                        ?.split(",")
                        ?.map(String::trim)
                        ?.filter(String::isNotBlank)
                        ?.let(::addAll)

                    this@SeriesDto.seriesType
                        ?.takeIf { it.isNotBlank() }
                        ?.let(::add)

                    this@SeriesDto.ageRating
                        ?.takeIf { it.isNotBlank() }
                        ?.let(::add)
                }.joinToString(", ")

                status = when (this@SeriesDto.status?.lowercase()) {
                    "en emisión" -> SManga.ONGOING
                    "finalizado" -> SManga.COMPLETED
                    else -> SManga.UNKNOWN
                }
            }
        }
    }

    @Serializable
    private data class ChapterDto(
        val id: Int,
        @SerialName("series_id")
        val seriesId: Int,
        @SerialName("chapter_number")
        val chapterNumber: Double,
        val title: String? = null,
        val volume: Int? = null,
        @SerialName("page_count")
        val pageCount: Int = 0,
        @SerialName("coin_cost")
        val coinCost: Int = 0,
        @SerialName("is_published")
        val isPublished: Boolean = false,
        @SerialName("is_unlocked")
        val isUnlocked: Boolean = true,
        @SerialName("access_status")
        val accessStatus: String? = null,
        @SerialName("available_at")
        val availableAt: String? = null,
        @SerialName("published_at")
        val publishedAt: String? = null,
    ) {

        fun toSChapter(): SChapter {
            val number = chapterNumber
                .toString()
                .removeSuffix(".0")

            return SChapter.create().apply {
                url = "/reader?series=$seriesId&chapter=$id"

                name = title
                    ?.takeIf { it.isNotBlank() }
                    ?: "Capítulo $number"

                chapter_number = chapterNumber.toFloat()

                date_upload = parseDate(
                    publishedAt ?: availableAt,
                )
            }
        }
    }

    private fun parseDate(value: String?): Long {
        if (value.isNullOrBlank()) {
            return 0L
        }

        return runCatching {
            Instant.parse(value).toEpochMilli()
        }.getOrDefault(0L)
    }
}
