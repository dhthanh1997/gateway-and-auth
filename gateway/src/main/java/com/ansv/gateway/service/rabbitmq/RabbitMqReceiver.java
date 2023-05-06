package com.ansv.gateway.service.rabbitmq;

import com.ansv.gateway.dto.response.UserDTO;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.annotation.RabbitListenerConfigurer;
import org.springframework.amqp.rabbit.listener.RabbitListenerEndpointRegistrar;
import org.springframework.stereotype.Component;


@Component
public class RabbitMqReceiver implements RabbitListenerConfigurer {

    private static final Logger logger = LoggerFactory.getLogger(RabbitMqReceiver.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    public UserDTO userDTO = new UserDTO();

    public RabbitMqReceiver() {
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.configure(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT, true);
    }

    @RabbitListener(queues = "${spring.rabbitmq.queue}")
    public void receivedMessage(UserDTO user){
        logger.info("User Details Received is.. " + user.getUsername());
        userDTO = user;
    }

    @RabbitListener(queues = "${spring.rabbitmq.queue-human-received}")
    public void receivedMessageFromHumanResource(String jsonObject) throws JsonProcessingException {
        userDTO = objectMapper.readValue(jsonObject, UserDTO.class);
    }

    @Override
    public void configureRabbitListeners(RabbitListenerEndpointRegistrar rabbitListenerEndpointRegistrar) {

    }

}
