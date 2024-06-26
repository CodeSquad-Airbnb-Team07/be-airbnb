package team07.airbnb.exception.auth;

import org.springframework.http.HttpStatus;
import team07.airbnb.exception.ApplicationException;

public class AuthenticateException extends ApplicationException {

    public AuthenticateException(String message, String jwt) {
        super(message, HttpStatus.UNAUTHORIZED, jwt);
    }

    @Override
    public String getLog() {
        if (log == null) return "인증 정보 토큰 미포함";

        return "유효하지 않은 JWT 토큰\n" + log;
    }
}
