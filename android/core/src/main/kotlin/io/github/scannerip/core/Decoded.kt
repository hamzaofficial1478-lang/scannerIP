package io.github.scannerip.core

/** One code found in a camera frame or picture, whatever the barcode type. */
class Decoded(
    val format: String,
    val text: String,
    val raw: ByteArray,
    val isBinary: Boolean,
    /** Corner points (x, y) in the source image: top-left, top-right, bottom-right, bottom-left. */
    val corners: List<Pair<Int, Int>> = emptyList(),
) {
    fun payload(): Payload = classify(text, raw, isBinary)
    fun report(): Report = analyse(payload())

    /** Same content as another code? Used to avoid reporting one code over and over. */
    val key: String get() = if (isBinary) raw.toHex() else text
}
