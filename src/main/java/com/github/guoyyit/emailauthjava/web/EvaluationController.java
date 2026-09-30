package com.github.guoyyit.emailauthjava.web;

import com.github.guoyyit.emailauthjava.service.AuthenticationService;
import com.github.guoyyit.emailauthjava.service.EvaluationResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
        byte[] raw = request.getRawMessage() == null ? new byte[0]
                : request.getRawMessage().getBytes(StandardCharsets.UTF_8);
        return authenticationService.evaluate(request.getHeloDomain(), request.getClientIp(),
                request.getEnvelopeFrom(), raw);
    }
}
