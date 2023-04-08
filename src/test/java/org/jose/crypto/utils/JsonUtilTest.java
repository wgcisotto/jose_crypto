package org.jose.crypto.utils;

import org.jose.crypto.exception.JsonUtilException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class JsonUtilTest {

    @Test
    void jsonToObject() throws JsonUtilException {
        String person = "{\"name\": \"Bob\", \"age\": 10}";
        Object object = JsonUtil.jsonToObject(person, Object.class);
        assertNotNull(object);
    }

}