package io.security.authentication.util;

import jakarta.servlet.http.HttpServletRequest;

public class WebUtil {
    private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
    private static final String X_REQUEST_WITH = "X-Requested-With";
    private static final String CONTENT_TYPE = "Content-type";
    private static final String CONTENT_TYPE_JSON = "application/json";

    public static boolean isAjax(HttpServletRequest request) {
        return XML_HTTP_REQUEST.equals(request.getHeader(X_REQUEST_WITH));
    }

    public static boolean isContentTypeJson(HttpServletRequest request) {
        return request.getHeader(CONTENT_TYPE).contains(CONTENT_TYPE_JSON);
    }


}
