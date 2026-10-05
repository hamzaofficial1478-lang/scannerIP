package io.github.scannerip.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.ImageDecoder
import android.graphics.Paint
import android.graphics.Path
import android.net.Uri
import android.os.Build
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import io.github.scannerip.core.Decoded
import zxingcpp.BarcodeReader
import zxingcpp.BarcodeReader.Format

/**
 * Reads every kind of code with ZXing-C++ (the same library as the desktop
 * version): QR Code, Micro QR, rMQR, Aztec, Data Matrix, PDF417, MaxiCode and
 * the usual 1D barcodes. Rotated, inverted and small codes are fine.
 */
object CodeReader {
    fun newReader() = BarcodeReader(
        BarcodeReader.Options(tryHarder = true, tryRotate = true, tryInvert = true, tryDownscale = true),
    )

    fun convert(results: List<BarcodeReader.Result>): List<Decoded> = results.map { r ->
        val p = r.position
        Decoded(
            format = formatLabel(r.format),
            text = r.text.orEmpty(),
            raw = r.bytes ?: ByteArray(0),
            isBinary = r.contentType == BarcodeReader.ContentType.BINARY,
            corners = listOf(p.topLeft, p.topRight, p.bottomRight, p.bottomLeft).map { it.x to it.y },
        )
    }

    fun formatLabel(format: Format): String = when (format) {
        Format.QR_CODE, Format.QR_CODE_MODEL_2 -> "QR Code"
        Format.QR_CODE_MODEL_1 -> "QR Code (Model 1)"
        Format.MICRO_QR_CODE -> "Micro QR Code"
        Format.RMQR_CODE -> "rMQR Code"
        Format.AZTEC, Format.AZTEC_CODE, Format.AZTEC_RUNE -> "Aztec"
        Format.DATA_MATRIX -> "Data Matrix"
        Format.PDF_417, Format.COMPACT_PDF_417 -> "PDF417"
        Format.MICRO_PDF_417 -> "Micro PDF417"
        Format.MAXI_CODE -> "MaxiCode"
        Format.EAN_13 -> "EAN-13"
        Format.EAN_8 -> "EAN-8"
        Format.UPC_A -> "UPC-A"
        Format.UPC_E -> "UPC-E"
        Format.ISBN -> "ISBN"
        Format.CODE_128 -> "Code 128"
        Format.CODE_39, Format.CODE_39_STD, Format.CODE_39_EXT, Format.CODE_32, Format.PZN -> "Code 39"
        Format.CODE_93 -> "Code 93"
        Format.ITF, Format.ITF_14 -> "ITF"
        Format.CODABAR -> "Codabar"
        Format.DATA_BAR, Format.DATA_BAR_OMNI, Format.DATA_BAR_STK, Format.DATA_BAR_STK_OMNI,
        Format.DATA_BAR_LTD, Format.DATA_BAR_EXP, Format.DATA_BAR_EXP_STK -> "DataBar"
        else -> format.name.lowercase().replace('_', ' ').replaceFirstChar { it.uppercase() }
    }

    /** Load a picture the user chose, as a plain ARGB bitmap no bigger than [maxSide]. */
    fun loadBitmap(context: Context, uri: Uri, maxSide: Int = 2400): Bitmap {
        val bitmap = if (Build.VERSION.SDK_INT >= 28) {
            ImageDecoder.decodeBitmap(ImageDecoder.createSource(context.contentResolver, uri)) { decoder, info, _ ->
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE // the decoder needs to read the pixels
                val longest = maxOf(info.size.width, info.size.height)
                if (longest > maxSide) {
                    val scale = maxSide.toFloat() / longest
                    decoder.setTargetSize((info.size.width * scale).toInt(), (info.size.height * scale).toInt())
                }
            }
        } else {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            context.contentResolver.openInputStream(uri).use { BitmapFactory.decodeStream(it, null, bounds) }
            var sample = 1
            while (maxOf(bounds.outWidth, bounds.outHeight) / sample > maxSide) sample *= 2
            val options = BitmapFactory.Options().apply { inSampleSize = sample; inPreferredConfig = Bitmap.Config.ARGB_8888 }
            context.contentResolver.openInputStream(uri).use { BitmapFactory.decodeStream(it, null, options) }
                ?: throw IllegalArgumentException("That file isn't a picture we can read.")
        }
        return if (bitmap.config == Bitmap.Config.ARGB_8888) bitmap else bitmap.copy(Bitmap.Config.ARGB_8888, false)
    }

    fun decodeBitmap(bitmap: Bitmap): List<Decoded> = convert(newReader().read(bitmap))

    /** Copy of [bitmap] with a green outline round every code found. */
    fun annotate(bitmap: Bitmap, codes: List<Decoded>): Bitmap {
        val copy = bitmap.copy(Bitmap.Config.ARGB_8888, true)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.STROKE
            strokeWidth = maxOf(4f, copy.width / 120f)
            color = 0xFF00E676.toInt()
        }
        val canvas = Canvas(copy)
        for (code in codes.filter { it.corners.size == 4 }) {
            val path = Path()
            code.corners.forEachIndexed { i, (x, y) ->
                if (i == 0) path.moveTo(x.toFloat(), y.toFloat()) else path.lineTo(x.toFloat(), y.toFloat())
            }
            path.close()
            canvas.drawPath(path, paint)
        }
        return copy
    }
}

/** Feeds camera frames to ZXing-C++ on CameraX's analysis thread. */
class CodeAnalyzer(private val onCodes: (List<Decoded>) -> Unit) : ImageAnalysis.Analyzer {
    private val reader = CodeReader.newReader()

    override fun analyze(image: ImageProxy) {
        image.use {
            val codes = try { CodeReader.convert(reader.read(it)) } catch (_: Exception) { emptyList() }
            onCodes(codes)
        }
    }
}
