package org.bouncycastle.digisign.bouncycastlesigning.loader;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;

@Configuration
public class BouncyCastleLoader {

    @EventListener
    public void loadOnApplicationEvent(ContextRefreshedEvent event) {
        Security.addProvider(new BouncyCastleProvider());
    }
}
