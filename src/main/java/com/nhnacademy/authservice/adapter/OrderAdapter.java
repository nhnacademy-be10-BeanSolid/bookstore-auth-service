package com.nhnacademy.authservice.adapter;

import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(name = "order-api")
public interface OrderAdapter {

}
