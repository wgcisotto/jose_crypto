package org.jose.crypto.utils;

import org.jose.crypto.exception.JsonUtilException;
import org.jose.crypto.model.FlattenedSignature;

public class SignUtil {

    private SignUtil(){

    }

    public static String fromFlattenedToCompactSignature(String signature) throws JsonUtilException {
        FlattenedSignature flattenedSignature = (FlattenedSignature) JsonUtil.jsonToObject(signature, FlattenedSignature.class);
        return flattenedSignature.toCompactSignature();
    }

}
