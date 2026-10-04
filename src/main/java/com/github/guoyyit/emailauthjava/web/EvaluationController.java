package com.github.guoyyit.emailauthjava.web;

import com.github.guoyyit.emailauthjava.service.AuthenticationService;
import com.github.guoyyit.emailauthjava.service.EvaluationResult;
import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.error.AuthError;
import com.github.guoyyit.emailauthjava.error.ResourceLimitException;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api")
public class EvaluationController {
    private final AuthenticationService authenticationService;
    private final AuthProperties properties;

    public EvaluationController(AuthenticationService authenticationService,
                                AuthProperties properties) {
        this.authenticationService = authenticationService;
        this.properties = properties;
    }

    @PostMapping(path = "/evaluate", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public EvaluationResult evaluate(@RequestBody EvaluateRequest request) {
        byte[] raw = request.getRawMessage() == null ? new byte[0]
                : request.getRawMessage().getBytes(StandardCharsets.UTF_8);
        return authenticationService.evaluate(request.getHeloDomain(), request.getClientIp(),
                request.getEnvelopeFrom(), raw);
    }

    /**
     * 无损 8 位提交：请求体即 RFC 5322 邮件原文的原始字节，不经过任何字符集解码，
     * 非 UTF-8 字节原样进入评估。信封参数通过查询参数传递（均为 ASCII）。
     * 原有 JSON 提交方式保持兼容，存量调用无需迁移。
     */
    @PostMapping(path = "/evaluate/raw",
            consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public EvaluationResult evaluateRaw(@RequestBody byte[] rawMessage,
                                        @RequestParam(value = "heloDomain", required = false)
                                        String heloDomain,
                                        @RequestParam(value = "clientIp", required = false)
                                        String clientIp,
                                        @RequestParam(value = "envelopeFrom", required = false)
                                        String envelopeFrom) {
        byte[] raw = rawMessage == null ? new byte[0] : rawMessage;
        if (raw.length > properties.getLimits().getMaxMessageBytes()) {
            throw new ResourceLimitException(AuthError.MESSAGE_TOO_LARGE,
                    "message size " + raw.length + " exceeds limit "
                            + properties.getLimits().getMaxMessageBytes());
        }
        return authenticationService.evaluate(heloDomain, clientIp, envelopeFrom, raw);
    }
}
