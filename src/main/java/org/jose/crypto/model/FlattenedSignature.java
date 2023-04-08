package org.jose.crypto.model;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.StringJoiner;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FlattenedSignature {

    @JsonProperty("payload")
    private String payload;

    @JsonProperty("protected")
    private String protectedData;

    @JsonProperty("signature")
    private String signature;

    public String toJson() throws JsonProcessingException {
        return new ObjectMapper().writeValueAsString(this);
    }

    public String toCompactSignature(){
        return new StringJoiner(".")
                .add(protectedData)
                .add(payload)
                .add(signature)
                .toString();
    }

}
