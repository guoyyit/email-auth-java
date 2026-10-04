package com.github.guoyyit.emailauthjava.web;

import com.github.guoyyit.emailauthjava.service.AuthenticationService;
import com.github.guoyyit.emailauthjava.service.EvaluationResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api")
public class EvaluationController {
    private final AuthenticationService authenticationService;

    public EvaluationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping(path = "/evaluate", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public EvaluationResult evaluate(@RequestBody EvaluateRequest request) {
        byte[] raw = decodeRawMessage(request);
        return authenticationService.evaluate(request.getHeloDomain(), request.getClientIp(),
                request.getEnvelopeFrom(), raw);
    }

    private byte[] decodeRawMessage(EvaluateRequest request) {
        String encoded = request.getRawMessageBase64();
        if (encoded != null) {
            try {
                return Base64.getDecoder().decode(normalizeBase64(encoded));
            } catch (IllegalArgumentException e) {
                throw new InvalidPayloadException("rawMessageBase64 is not valid Base64", e);
            }
        }
        return request.getRawMessage() == null ? new byte[0]
                : request.getRawMessage().getBytes(StandardCharsets.UTF_8);
    }

    private static String normalizeBase64(String value) {
        String compact = value.replaceAll("\\s", "");
        int padding = (4 - compact.length() % 4) % 4;
        return compact + "=".repeat(padding);
    }
}
