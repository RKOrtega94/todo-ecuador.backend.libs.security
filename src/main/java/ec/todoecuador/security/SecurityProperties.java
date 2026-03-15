package ec.todoecuador.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Setter
@Getter
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {
    private List<String> publicPaths;
    private List<String> publicGetPaths;
    private List<String> publicPostPaths;
    private List<String> publicPutPaths;
    private List<String> publicDeletePaths;
    private String jwtSigningKey;
    private String issuerUri;
}
