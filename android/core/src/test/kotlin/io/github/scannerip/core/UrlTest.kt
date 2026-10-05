package io.github.scannerip.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/** UrlParts has to agree with Python's urlsplit, which the desktop checks were written against. */
class UrlTest {
    @Test
    fun splitsLikePython() {
        val p = UrlParts.split("HTTPS://user:pw@Example.COM:8443/a/b?x=1&y=2#frag")
        assertEquals("https", p.scheme)
        assertEquals("user:pw@Example.COM:8443", p.netloc)
        assertEquals("example.com", p.hostname)
        assertEquals(8443, p.port)
        assertEquals("/a/b", p.path)
        assertEquals("x=1&y=2", p.query)
        assertEquals("frag", p.fragment)
    }

    @Test
    fun opaqueSchemes() {
        val js = UrlParts.split("javascript:alert(1)")
        assertEquals("javascript", js.scheme)
        assertEquals("", js.netloc)
        assertEquals("alert(1)", js.path)
        val mail = UrlParts.split("mailto:bob@example.com?subject=Hi")
        assertEquals("bob@example.com", mail.path)
        assertEquals("subject=Hi", mail.query)
    }

    @Test
    fun ipv6AndPorts() {
        val p = UrlParts.split("http://[FE80::1]:8080/")
        assertEquals("fe80::1", p.hostname)
        assertEquals(8080, p.port)
        assertNull(UrlParts.split("http://example.com/").port)
        assertFailsWith<IllegalArgumentException> { UrlParts.split("http://example.com:abc/").port }
        assertFailsWith<IllegalArgumentException> { UrlParts.split("http://example.com:70000/").port }
    }

    @Test
    fun whitespaceAndTabsAreDropped() {
        assertEquals("example.com", UrlParts.split("  http://exam\tple.com/ ").hostname)
    }

    @Test
    fun percentDecodingIsLenient() {
        assertEquals("hi you", percentDecode("hi%20you"))
        assertEquals("café", percentDecode("caf%C3%A9"))
        assertEquals("100%", percentDecode("100%"))
        assertEquals("%zz", percentDecode("%zz"))
        assertEquals("a+b", percentDecode("a+b")) // unlike URLDecoder
    }

    @Test
    fun queryParsingLikeParseQs() {
        val q = parseQuery("a=1&b=two+words&a=3&empty=&flag&c=%2F")
        assertEquals(listOf("1", "3"), q["a"])
        assertEquals(listOf("two words"), q["b"])
        assertEquals(listOf("/"), q["c"])
        assertNull(q["empty"])
        assertNull(q["flag"])
    }

    @Test
    fun ipLiterals() {
        assertEquals("203.0.113.7", IpLiteral.format(IpLiteral.parseV4("203.0.113.7")!!))
        assertNull(IpLiteral.parseV4("203.0.113.07")) // leading zero, like Python
        assertNull(IpLiteral.parseV4("256.1.1.1"))
        assertNull(IpLiteral.parseV4("example.com"))
        assertEquals(16, IpLiteral.parseV6("::1")!!.size)
        assertEquals(16, IpLiteral.parseV6("2001:db8::8a2e:370:7334")!!.size)
        assertEquals(16, IpLiteral.parseV6("::ffff:192.0.2.1")!!.size)
        assertNull(IpLiteral.parseV6("1::2::3"))
        assertNull(IpLiteral.parseV6("hello"))
        assertNull(IpLiteral.parseV6("12345::1"))
    }
}
