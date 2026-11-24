package eu.kanade.tachiyomi.extension.es.aedex

import kotlin.math.roundToInt

// The reader's 8x8 plan drawn from the page key
internal class AedexSlicePlanner(
    private val key: ByteArray,
    private val width: Int,
    private val height: Int,
    private val gutter: Int,
) {
    private val random = mulberry32(key)

    private val columnWidths = boundaries(random, width - gutter * 16)
    private val rowHeights = boundaries(random, height - gutter * 16)

    private val columns = permutation(random)
    private val rows = permutation(random)

    private val inverseColumns = inverse(columns)
    private val inverseRows = inverse(rows)

    private val sourceColumnOffsets = sourceOffsets(columnWidths, gutter)
    private val sourceRowOffsets = sourceOffsets(rowHeights, gutter)

    private val destinationColumnOffsets = destinationOffsets(columnWidths)
    private val destinationRowOffsets = destinationOffsets(rowHeights)

    fun slices(): List<AedexSlice> = buildList(GRID * GRID) {
        for (y in 0 until GRID) {
            for (x in 0 until GRID) {
                val sourceColumn = inverseColumns[x]
                val sourceRow = inverseRows[y]

                add(
                    AedexSlice(
                        sx = sourceColumnOffsets[sourceColumn],
                        sy = sourceRowOffsets[sourceRow],
                        sw = columnWidths[x],
                        sh = rowHeights[y],
                        dx = destinationColumnOffsets[x],
                        dy = destinationRowOffsets[y],
                    ),
                )
            }
        }
    }

    private fun sourceOffsets(sizes: IntArray, gutter: Int): IntArray {
        val offsets = IntArray(GRID)
        var position = gutter

        for (i in 0 until GRID) {
            offsets[i] = position
            position += sizes[i] + gutter * 2
        }

        return offsets
    }

    private fun destinationOffsets(sizes: IntArray): IntArray {
        val offsets = IntArray(GRID)
        var position = 0

        for (i in 0 until GRID) {
            offsets[i] = position
            position += sizes[i]
        }

        return offsets
    }

    private fun inverse(order: IntArray): IntArray {
        val result = IntArray(GRID)

        for (i in order.indices) {
            result[order[i]] = i
        }

        return result
    }

    private fun boundaries(random: () -> Double, total: Int): IntArray {
        val sizes = IntArray(GRID)
        val base = total shr 3
        var remaining = total

        for (i in 0 until GRID - 1) {
            val minimum = MIN_TILE
            val maximum = remaining - MIN_TILE * (GRID - 1 - i)
            val size = (base * (0.65 + 0.7 * random())).roundToInt()
                .coerceIn(minimum, maximum)

            sizes[i] = size
            remaining -= size
        }

        sizes[GRID - 1] = remaining
        return sizes
    }

    private fun permutation(random: () -> Double): IntArray {
        val order = IntArray(GRID) { it }

        for (i in GRID - 1 downTo 1) {
            val j = (random() * (i + 1)).toInt()
            order[i] = order[j].also { order[j] = order[i] }
        }

        return order
    }

    private fun mulberry32(key: ByteArray): () -> Double {
        var seed = 0

        for (byte in key) {
            seed = seed * 31 + (byte.toInt() and 0xFF)
        }

        return {
            seed += -0x2938460B
            var t = seed
            t = (t xor (t ushr 15)) * (t or 1)
            t = t xor (t + (t xor (t ushr 7)) * (t or 61))
            t = t xor (t ushr 14)
            t.toUInt().toDouble() / 4294967296.0
        }
    }

    companion object {
        private const val GRID = 8
        private const val MIN_TILE = 16
    }
}

internal data class AedexSlice(
    val sx: Int,
    val sy: Int,
    val sw: Int,
    val sh: Int,
    val dx: Int,
    val dy: Int,
)
