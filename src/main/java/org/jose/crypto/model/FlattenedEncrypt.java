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
public class FlattenedEncrypt {

    @JsonProperty("encrypted_key")
    private String encryptedKey;

    @JsonProperty("protected")
    private String protectedData;

    @JsonProperty("iv")
    private String iv;

    @JsonProperty("ciphertext")
    private String ciphertext;

    @JsonProperty("tag")
    private String tag;

    @JsonProperty("payload")
    private String payload;

    @JsonProperty("signature")
    private String signature;

    public String toJson() throws JsonProcessingException {
        return new ObjectMapper().writeValueAsString(this);
    }

    public String toCompactEncrypt(){
        return new StringJoiner(".")
                .add(protectedData)
                .add(encryptedKey)
                .add(iv)
                .add(ciphertext)
                .add(tag)
                .toString();
    }

}
