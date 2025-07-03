package org.bouncycastle.digisign.bouncycastlesigning.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Data
@Component
@ConfigurationProperties(prefix = "digisign")
public class DigiSignProperties {

    private String keyStore;

    private String keyStorePassword;

    private String privateKeyPassword;

    private String alias;

    private String keyStoreType;
}
