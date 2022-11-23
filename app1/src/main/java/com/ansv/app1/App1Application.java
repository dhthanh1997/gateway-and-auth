package com.ansv.app1;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

@SpringBootApplication
@EnableEurekaClient
public class App1Application {

	public static void main(String[] args) {
		SpringApplication.run(App1Application.class, args);
	}

}
