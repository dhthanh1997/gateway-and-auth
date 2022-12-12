package com.ansv.authorizationserver.service.impl.rabbitmq;

import com.ansv.authorizationserver.dto.response.UserDTO;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;


@Service
public class RabbitMqSender {

    @Autowired
    private AmqpTemplate rabbitTemplate;

    @Value("${spring.rabbitmq.exchange:#{null}}")
    private String exchange;

    @Value("${spring.rabbitmq.routingkey:#{null}}")
    private String routingkey;


    public void sender(UserDTO user) {

        rabbitTemplate.convertAndSend(exchange, routingkey, user
        );
    }

    public void sender(String username) {
        rabbitTemplate.convertAndSend(exchange, routingkey, username);
    }

}
