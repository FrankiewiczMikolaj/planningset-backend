package com.planningset;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/test")
public class testController {
    @GetMapping()
    public TestRecord getUsers(){
        return new TestRecord("123");
    }
}
record TestRecord(String data) {
}
