package com.ansv.gateway.service.rabbitmq;

import com.ansv.gateway.dto.response.UserDTO;
import com.ansv.gateway.util.DataUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.core.MessagePostProcessor;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.core.Queue;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.util.concurrent.ListenableFuture;

import java.util.UUID;


@Service
public class RabbitMqSender {

    private static final Logger logger = LoggerFactory.getLogger(RabbitMqSender.class);

    @Autowired
    private AmqpTemplate rabbitTemplate;

//    @Autowired
//    private RabbitMqReceiver rabbitMqReceiver;

    @Value("${spring.rabbitmq.exchange:#{null}}")
    private String exchange;

    // to task
    @Value("${spring.rabbitmq.routingkey:#{null}}")
    private String routingkey;

    // to human
    @Value("${spring.rabbitmq.routingkey-human:#{null}}")
    private String routingkeyHuman;


    private final ObjectMapper objectMapper = new ObjectMapper();

    public RabbitMqSender() {
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.configure(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT, true);
    }

    // sender to task service
    public void sender(UserDTO user) {
        rabbitTemplate.convertAndSend(exchange, routingkey, user);
    }
    // end

    // sender to human service for check username
    public void senderUsernameToHuman(UserDTO user) {
        rabbitTemplate.convertAndSend(exchange, routingkeyHuman, user);
    }
    // end

    // sender to human and task service for add user
    public void senderUserObject(UserDTO item) {
        rabbitTemplate.convertAndSend(exchange, routingkeyHuman, item);
//        rabbitTemplate.convertAndSend(exchange, routingkey, item);

    }


}
