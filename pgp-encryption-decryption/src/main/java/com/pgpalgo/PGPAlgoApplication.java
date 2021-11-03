package com.pgpalgo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class PGPAlgoApplication {

    private static Logger logger = LoggerFactory.getLogger(PGPAlgoApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(PGPAlgoApplication.class, args);

        logger.info("Application started!");
    }

}
