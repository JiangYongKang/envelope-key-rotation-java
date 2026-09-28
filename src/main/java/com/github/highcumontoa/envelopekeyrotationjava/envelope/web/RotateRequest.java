package com.github.highcumontoa.envelopekeyrotationjava.envelope.web;

import java.util.List;

/** 轮换请求。 */
public record RotateRequest(String caller, List<String> roles) {
}
