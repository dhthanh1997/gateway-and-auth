package com.ansv.euruka;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

@SpringBootApplication
@EnableEurekaServer
public class EurukaApplication {

	public static void main(String[] args) {
		SpringApplication.run(EurukaApplication.class, args);
	}

}
