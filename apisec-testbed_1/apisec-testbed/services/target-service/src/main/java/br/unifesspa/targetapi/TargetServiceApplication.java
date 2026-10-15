package br.unifesspa.targetapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import br.unifesspa.targetapi.config.VulnFlags;

@SpringBootApplication
@EnableConfigurationProperties(VulnFlags.class)
public class TargetServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(TargetServiceApplication.class, args);
    }
}
