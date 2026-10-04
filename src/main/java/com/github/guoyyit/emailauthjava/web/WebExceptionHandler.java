package com.github.guoyyit.emailauthjava.web;

import com.github.guoyyit.emailauthjava.error.ResourceLimitException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class WebExceptionHandler {
    @ExceptionHandler(InvalidPayloadException.class)
    public ResponseEntity<ErrorResponse> handleInvalidPayload(InvalidPayloadException exception) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse("INVALID_PAYLOAD", exception.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(
            HttpMessageNotReadableException exception) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse("INVALID_PAYLOAD", "request body is not valid JSON"));
    }

    @ExceptionHandler(ResourceLimitException.class)
    public ResponseEntity<ErrorResponse> handleLimit(ResourceLimitException exception) {
        return ResponseEntity.status(HttpStatus.REQUEST_ENTITY_TOO_LARGE)
                .body(new ErrorResponse(exception.getError().name(), exception.getMessage()));
    }
}
