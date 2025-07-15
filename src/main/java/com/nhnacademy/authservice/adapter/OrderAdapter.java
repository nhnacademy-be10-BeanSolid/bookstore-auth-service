package com.nhnacademy.authservice.adapter;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "order-api")
public interface OrderAdapter {

    @GetMapping("/internal/orders/id")
    Long getIdByOrderNumber(@RequestParam String orderNumber);

}
