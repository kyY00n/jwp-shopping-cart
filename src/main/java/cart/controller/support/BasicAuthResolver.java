package cart.controller.support;

import static org.apache.tomcat.util.codec.binary.Base64.decodeBase64;

import cart.dto.BasicCredentials;
import cart.service.AuthService;
import java.util.Objects;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

@Component
public class BasicAuthResolver implements HandlerMethodArgumentResolver {

    private static final String AUTH_HEADER_NAME = "Authorization";
    private static final String AUTHORIZATION_SCHEME_BASIC = "Basic";
    private static final String DELIMITER = ":";

    private final AuthService authService;

    public BasicAuthResolver(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(BasicAuth.class);
    }

    @Override
    public BasicCredentials resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                            NativeWebRequest webRequest, WebDataBinderFactory binderFactory)
            throws Exception {
        String authorizationHeader = getAuthorizationHeader(parameter, webRequest);
        HttpSession session = getHttpSession(webRequest);

        return Optional.ofNullable((BasicCredentials) session.getAttribute(authorizationHeader))
                .orElseGet(() -> {
                    BasicCredentials createdCredential = getBasicCredentials(authorizationHeader);
                    session.setAttribute(authorizationHeader, createdCredential);
                    return createdCredential;
                });
    }

    private String getAuthorizationHeader(MethodParameter parameter, NativeWebRequest webRequest)
            throws MissingRequestHeaderException {
        String authorizationHeader = webRequest.getHeader(AUTH_HEADER_NAME);
        if (authorizationHeader == null) {
            throw new MissingRequestHeaderException(AUTH_HEADER_NAME, parameter);
        }
        return authorizationHeader;
    }

    private HttpSession getHttpSession(NativeWebRequest webRequest) {
        HttpServletRequest httpServletRequest = Objects.requireNonNull(
                webRequest.getNativeRequest(HttpServletRequest.class));
        HttpSession session = httpServletRequest.getSession();
        return session;
    }

    private BasicCredentials getBasicCredentials(String authorizationHeader) {
        BasicCredentials credentials = extractBasicCredentials(authorizationHeader);
        authService.authenticateUser(credentials);
        return credentials;
    }

    private BasicCredentials extractBasicCredentials(String authorizationHeader) {
        if (isNotBasicAuth(authorizationHeader)) {
            throw new IllegalArgumentException("올바른 인증방식을 사용해주세요.");
        }

        String credentials = authorizationHeader.substring(AUTHORIZATION_SCHEME_BASIC.length()).trim();

        String[] splitCredentials = new String(decodeBase64(credentials)).split(DELIMITER);
        return new BasicCredentials(splitCredentials[0], splitCredentials[1]);
    }

    private boolean isNotBasicAuth(String authorization) {
        return !authorization.toLowerCase().startsWith(AUTHORIZATION_SCHEME_BASIC.toLowerCase());
    }
}
