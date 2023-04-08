package org.jose.crypto.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.jose.crypto.exception.JsonUtilException;

import java.io.IOException;
import java.util.Objects;

@Slf4j
public class JsonUtil {

    private JsonUtil(){

    }

    /**
     * @param json
     * @param clazz
     * @return Object
     * @throws JsonUtilException
     */
    public static Object jsonToObject(String json, Class<?> clazz) throws JsonUtilException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(json, clazz);
        } catch (IOException e) {
            if(Objects.isNull(clazz)){
                throw new JsonUtilException("Class to convert is null", e);
            }
            throw new JsonUtilException("Error to convert JSON to Object", e);
        }
    }

}
