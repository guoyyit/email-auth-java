package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.error.AuthError;
import com.github.guoyyit.emailauthjava.error.ResourceLimitException;
import com.github.guoyyit.emailauthjava.message.MessageParser;
import com.github.guoyyit.emailauthjava.message.RawMessage;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MessageParserTest {
    private final MessageParser parser = new MessageParser(new AuthProperties());

    @Test
    void unfoldsFoldedHeaders() {
        RawMessage message = parser.parse("h", "1.1.1.1",
                "Subject: one\r\n two\r\nFrom: a@b.com\r\n\r\nBody\r\n"
                        .getBytes(StandardCharsets.UTF_8));
        assertThat(message.getFirstHeader("Subject")).isEqualTo("one two");
        assertThat(new String(message.getBody(), StandardCharsets.UTF_8)).isEqualTo("Body\r\n");
    }

    @Test
    void acceptsBareLineFeeds() {
        RawMessage message = parser.parse("h", "1.1.1.1",
                "From: a@b.com\nX-Tag: v\n\nbody\n".getBytes(StandardCharsets.UTF_8));
        assertThat(message.getFirstHeader("X-Tag")).isEqualTo("v");
        assertThat(new String(message.getBody(), StandardCharsets.UTF_8)).isEqualTo("body\n");
    }

    @Test
    void preservesEightBitBody() {
        byte[] raw = "From: a@b.com\r\n\r\nHéllo→€\r\n".getBytes(StandardCharsets.UTF_8);
        RawMessage message = parser.parse("h", "1.1.1.1", raw);
        assertThat(new String(message.getBody(), StandardCharsets.UTF_8))
                .isEqualTo("Héllo→€\r\n");
    }

    @Test
    void keepsHeaderNameCase() {
        RawMessage message = parser.parse("h", "1.1.1.1",
                "DKIM-Signature: v=1\r\n\r\nx".getBytes(StandardCharsets.UTF_8));
        assertThat(message.getHeaders("dkim-signature").get(0).getRawName())
                .isEqualTo("DKIM-Signature");
    }

    @Test
    void rejectsOversizedMessage() {
        AuthProperties props = new AuthProperties();
        props.getLimits().setMaxMessageBytes(10);
        assertThatThrownBy(() -> new MessageParser(props).parse("h", "1.1.1.1",
                new byte[42]))
                .isInstanceOf(ResourceLimitException.class)
                .extracting(ex -> ((ResourceLimitException) ex).getError())
                .isEqualTo(AuthError.MESSAGE_TOO_LARGE);
    }

    @Test
    void rejectsMalformedHeader() {
        assertThatThrownBy(() -> parser.parse("h", "1.1.1.1",
                "BrokenHeader\r\n\r\nx".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(ResourceLimitException.class)
                .extracting(ex -> ((ResourceLimitException) ex).getError())
                .isEqualTo(AuthError.MALFORMED_HEADER);
    }

    @Test
    void enforcesHeaderCount() {
        AuthProperties props = new AuthProperties();
        props.getLimits().setMaxHeaders(2);
        byte[] raw = "A: 1\r\nB: 2\r\nC: 3\r\n\r\nx".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> new MessageParser(props).parse("h", "1.1.1.1", raw))
                .isInstanceOf(ResourceLimitException.class)
                .extracting(ex -> ((ResourceLimitException) ex).getError())
                .isEqualTo(AuthError.TOO_MANY_HEADERS);
    }
}
