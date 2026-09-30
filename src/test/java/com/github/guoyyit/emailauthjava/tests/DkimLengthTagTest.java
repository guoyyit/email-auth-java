package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.dkim.Canonicalizer;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DkimLengthTagTest {

    @Test
    void simpleBodyLengthLimitTruncatesTrailingContent() {
        byte[] body = "signed-part\r\nunsigned-trailer\r\n"
                .getBytes(StandardCharsets.UTF_8);
        byte[] canonical = Canonicalizer.canonicalizeBody(
                body, Canonicalizer.BodyMode.SIMPLE, 13);
        assertEquals("signed-part\r\n",
                new String(canonical, StandardCharsets.UTF_8));
    }

    @Test
    void relaxedBodyLengthLimitTruncates() {
        byte[] body = "abc\r\nrest-ignored\r\n".getBytes(StandardCharsets.UTF_8);
        byte[] canonical = Canonicalizer.canonicalizeBody(
                body, Canonicalizer.BodyMode.RELAXED, 5);
        assertEquals("abc\r\n", new String(canonical, StandardCharsets.UTF_8));
    }
}
