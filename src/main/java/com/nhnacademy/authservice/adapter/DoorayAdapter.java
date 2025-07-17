package com.nhnacademy.authservice.adapter;

import com.nhnacademy.authservice.client.dooray.MessagePayload;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "DoorayAdapter", url = "https://nhnacademy.dooray.com/services/3204376758577275363/4071284119244117501/RibHlHtpSlCOQ1Kesn_0KQ")
public interface DoorayAdapter {

    @PostMapping
    String sendMessage(@RequestBody MessagePayload messagePayload);
}
