package com.nhnacademy.authservice.client.dooray;

import lombok.*;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MessagePayload {
    private String botName;
    private String text;
    private List<Attachment> attachments;
}
