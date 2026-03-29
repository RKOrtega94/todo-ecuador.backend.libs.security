package ec.todoecuador.security.session;

import org.springframework.security.core.context.SecurityContextHolder;

public class SessionUtils {
    private SessionUtils() {
    }

    public static String getClaim(String claim) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken jwtAuthenticationToken) {
            return (String) jwtAuthenticationToken.getTokenAttributes().get(claim);
        }
        return null;
    }

    public static String getSubject() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            return authentication.getName();
        }
        return null;
    }
}
