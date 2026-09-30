package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.mail.MailParseException;
import com.github.guoyyit.emailauthjava.mail.MailParser;
import com.github.guoyyit.emailauthjava.mail.ParsedMail;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MailParserTest {

    private final MailParser parser = new MailParser(new AuthProperties());

    @Test
    void parsesBasicCrlfMessage() {
        ParsedMail mail = parser.parse(
                "From: alice@example.com\r\nSubject: hi\r\n\r\nhello\r\n"
                        .getBytes(StandardCharsets.UTF_8));
        assertEquals("alice@example.com", mail.getFirstHeader("From"));
        assertEquals("hi", mail.getFirstHeader("Subject"));
        assertArrayEquals("hello\r\n".getBytes(StandardCharsets.UTF_8), mail.getRawBody());
    }

    @Test
    void unfoldsFoldedHeaders() {
        ParsedMail mail = parser.parse(
                ("Subject: first\r\n second\r\n\tpart\r\nFrom: a@b.example\r\n\r\nx")
                        .getBytes(StandardCharsets.UTF_8));
        assertEquals("first second\tpart", mail.getFirstHeader("Subject"));
    }

    @Test
    void toleratesBareLfLineEndings() {
        ParsedMail mail = parser.parse(
                "From: alice@example.com\nSubject: hi\n\nbody\n"
                        .getBytes(StandardCharsets.UTF_8));
        assertEquals("alice@example.com", mail.getFirstHeader("From"));
        assertEquals("body\n", new String(mail.getRawBody(), StandardCharsets.UTF_8));
    }

    @Test
    void preservesEightBitBodyBytes() {
        byte[] body = new byte[]{(byte) 0xc3, (byte) 0xa9, 0x00, (byte) 0xff};
        byte[] raw = ("From: a@b.example\r\n\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] combined = new byte[raw.length + body.length];
        System.arraycopy(raw, 0, combined, 0, raw.length);
        System.arraycopy(body, 0, combined, raw.length, body.length);

        ParsedMail mail = parser.parse(combined);
        assertArrayEquals(body, mail.getRawBody());
    }

    @Test
    void headerNameIsCaseInsensitiveButPreserved() {
        ParsedMail mail = parser.parse(
                "X-Mixed: v\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        assertEquals("X-Mixed", mail.getHeaders().get(0).getRawName());
        assertEquals("v", mail.getFirstHeader("x-mIXED"));
    }

    @Test
    void rejectsOversizedMessage() {
        AuthProperties properties = new AuthProperties();
        properties.getLimits().setMaxMessageBytes(32);
        MailParser strict = new MailParser(properties);
        MailParseException ex = assertThrows(MailParseException.class,
                () -> strict.parse(new byte[1024]));
        assertTrue(ex.isSizeLimit());
    }

    @Test
    void rejectsMalformedHeaderWithoutColon() {
        MailParseException ex = assertThrows(MailParseException.class,
                () -> parser.parse("NotAHeader\r\n\r\nx".getBytes(StandardCharsets.UTF_8)));
        assertTrue(!ex.isSizeLimit());
    }

    @Test
    void enforcesHeaderCountLimit() {
        AuthProperties properties = new AuthProperties();
        properties.getLimits().setMaxHeaders(2);
        MailParser strict = new MailParser(properties);
        byte[] raw = ("A: 1\r\nB: 2\r\nC: 3\r\n\r\nx").getBytes(StandardCharsets.UTF_8);
        MailParseException ex = assertThrows(MailParseException.class, () -> strict.parse(raw));
        assertTrue(ex.isSizeLimit());
    }

    @Test
    void messageWithoutBodyIsAccepted() {
        ParsedMail mail = parser.parse(
                "From: a@b.example\r\nSubject: no body\r\n".getBytes(StandardCharsets.UTF_8));
        assertEquals("no body", mail.getFirstHeader("Subject"));
        assertEquals(0, mail.getRawBody().length);
    }
}
