'use strict';

function traceStack() {
    var stack = Java.use("java.lang.Exception").$new().getStackTrace();

    for (var i = 1; i < stack.length; i+= 1) {
        var element = stack[i];
        var className = element.getClassName();
        var methodName = element.getMethodName();
        var fileName = element.getFileName();
        var lineNumber = element.getLineNumber();

        console.log("Class name: " + className + " Method name: " + methodName + " File name: " + fileName + " Line number: " + lineNumber);
    }
}

function bytesToHex(bytes) {
    let result = "";

    for (let i = 0; i < bytes.length; i++) {
        let v = bytes[i];

        if (v < 0)
            v += 256;

        result += ("0" + v.toString(16)).slice(-2);
    }

    return result;
}

function bytesToHexRange(bytes, offset, length) {
    let result = "";
    const end = Math.min(offset + length, bytes.length);

    for (let i = offset; i < end; i++) {
        let v = bytes[i];

        if (v < 0)
            v += 256;

        result += ("0" + v.toString(16)).slice(-2);
    }

    return result;
}

function bytesToString(bytes) {
    let result = '';

    for (let i = 0; i < bytes.length; ++i) {
        let val = bytes[i] & 0xFF;  // Get unsigned byte value
        // Only convert printable ASCII characters (32-126); otherwise, use a placeholder (.)
        if (val >= 32 && val <= 126) {
            result += String.fromCharCode(val); // Convert only printable characters
        } else {
            result += '.';  // Replace non-printable characters with a dot
        }
    }
    return result;
}

function bytesToStringRange(bytes, offset, length) {
    let result = '';
    const end = Math.min(offset + length, bytes.length);

    for (let i = 0; i < end; ++i) {
        let val = bytes[i] & 0xFF;  // Get unsigned byte value
        // Only convert printable ASCII characters (32-126); otherwise, use a placeholder (.)
        if (val >= 32 && val <= 126) {
            result += String.fromCharCode(val); // Convert only printable characters
        } else {
            result += '.';  // Replace non-printable characters with a dot
        }
    }
    return result;
}

function logKey(key) {
    if (key === null)
        return;

    console.log("Key class: " + key.$className);
    console.log("Key algorithm: " + key.getAlgorithm());
    console.log("Key format: " + key.getFormat());

    const encoded = key.getEncoded();

    if (encoded !== null)
        console.log("Key bytes: " + bytesToHex(encoded));
}

function logAlgorithmParameters(params) {
    if (params === null)
        return;

    console.log("Parameters class: " + params.$className);
    console.log("Parameters algorithm: " + params.getAlgorithm());

    try {
        console.log("Parameters encoded: " +
            bytesToHex(params.getEncoded()));
    } catch (e) {
        console.log("Could not encode parameters: " + e);
    }
}

function logAlgorithmParameterSpec(params) {
    if (params === null)
        return;

    console.log("Parameter class: " + params.$className);

    if (params.$className === "javax.crypto.spec.IvParameterSpec") {

        const IvParameterSpec =
            Java.use("javax.crypto.spec.IvParameterSpec");

        const ivSpec =
            Java.cast(params, IvParameterSpec);

        console.log(
            "IV: " +
            bytesToHex(ivSpec.getIV())
        );
    }

    if (params.$className === "javax.crypto.spec.GCMParameterSpec") {

        const GCMParameterSpec =
            Java.use("javax.crypto.spec.GCMParameterSpec");

        const gcm =
            Java.cast(params, GCMParameterSpec);

        console.log(
            "IV/nonce: " +
            bytesToHex(gcm.getIV())
        );

        console.log(
            "GCM tag bits: " +
            gcm.getTLen()
        );
    }
}

function describe_opmode(opmode) {
    if (opmode === 1) {
        console.log("opmode: " + opmode + " (ENCRYPT)");
    } else if (opmode === 2) {
        console.log("opmode: " + opmode + " (DECRYPT)");
    } else if (opmode === 3) {
        console.log("opmode: " + opmode + " (UNWRAP)");
    } else if (opmode === 4) {
        console.log("opmode: " + opmode + " (WRAP)");
    }
}

function byteArraySlice(src, offset, len) {
    // Slice a subset of a given array
    const result = [];

    for (let i = offset; i < offset + len; i++) {
        result.push(src[i]);
    }

    return result;
}

//  ------------
// | Main Logic |
//  ------------
Java.perform(function () {
    const Cipher = Java.use("javax.crypto.Cipher");

    //  -----------------------
    // | Cipher.init overloads |
    //  -----------------------
    try { // 1. [Cipher.init(int opmode, Certificate certificate) -> void]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.cert.Certificate"
        );

        initKey.implementation = function (opmode, certificate) {
            console.log("1. [Cipher.init(int opmode, Certificate certificate) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describe_opmode(opmode);

            console.log("Certificate type: " + certificate.getType());
            console.log("Public key: " + certificate.getPublicKey());

            //traceStack();

            return initKey.call(this, opmode, certificate);
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Cipher.init(int opmode, Certificate certificate, SecureRandom random) -> void]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.cert.Certificate",
            "java.security.SecureRandom"
        );

        initKey.implementation = function (opmode, certificate, random) {
            console.log("2. [Cipher.init(int opmode, Certificate certificate, SecureRandom random) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describe_opmode(opmode);

            console.log("Certificate type: " + certificate.getType());
            console.log("Public key: " + certificate.getPublicKey());
            console.log("SecureRandom: " + random);

            //traceStack();

            return initKey.call(this, opmode, certificate, random);
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 3. [Cipher.init(int opmode, Key key) -> void]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key"
        );

        initKey.implementation = function (opmode, key) {
            console.log("3. [Cipher.init(int opmode, Key key) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describe_opmode(opmode);

            logKey(key);

            //traceStack();

            return initKey.call(this, opmode, key);
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 4. [Cipher.init(int opmode, Key key, AlgorithmParameters params) -> void]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key",
            "java.security.AlgorithmParameters"
        );

        initKey.implementation = function (opmode, key, params) {
            console.log("4. [Cipher.init(int opmode, Key key, AlgorithmParameters params) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describe_opmode(opmode);

            logKey(key);
            logAlgorithmParameters(params);

            //traceStack();

            return initKey.call(this, opmode, key, params);
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 5. [Cipher.init(int opmode, Key key, AlgorithmParameterSpec params) -> void]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key",
            "java.security.spec.AlgorithmParameterSpec"
        );

        initKey.implementation = function (opmode, key, params) {
            console.log("5. [Cipher.init(int opmode, Key key, AlgorithmParameterSpec params) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describe_opmode(opmode);

            logKey(key);
            logAlgorithmParameterSpec(params);

            //traceStack();

            return initKey.call(this, opmode, key, params);
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 6. [Cipher.init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) -> void]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key",
            "java.security.spec.AlgorithmParameterSpec",
            "java.security.SecureRandom"
        );

        initKey.implementation = function (opmode, key, params, random) {
            console.log("6. [Cipher.init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describe_opmode(opmode);

            logKey(key);
            logAlgorithmParameterSpec(params);

            console.log("SecureRandom: " + random);

            //traceStack();

            return initKey.call(this, opmode, key, params, random);
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 7. [Cipher.init(int opmode, Key key, AlgorithmParameters params, SecureRandom random) -> void]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key",
            "java.security.AlgorithmParameters",
            "java.security.SecureRandom"
        );

        initKey.implementation = function (opmode, key, params, random) {
            console.log("7. [Cipher.init(int opmode, Key key, AlgorithmParameters params, SecureRandom random) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describe_opmode(opmode);

            logKey(key);
            logAlgorithmParameters(params);

            console.log("SecureRandom: " + random);

            //traceStack();

            return initKey.call(this, opmode, key, params, random);
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 8. [Cipher.init(int opmode, Key key, SecureRandom random) -> void]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key",
            "java.security.SecureRandom"
        );

        initKey.implementation = function (opmode, key, random) {
            console.log("8. [Cipher.init(int opmode, Key key, SecureRandom random) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describe_opmode(opmode);

            logKey(key);

            console.log("SecureRandom: " + random);

            //traceStack();

            return initKey.call(this, opmode, key, random);
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  -------------------------
    // | Cipher.update overloads |
    //  -------------------------
    try { // 1. [Cipher.update(byte[] input) -> byte[]]
        const updateKey = Cipher.update.overload(
            "[B"
        );

        updateKey.implementation = function (input) {
            console.log("1. [Cipher.update(byte[] input) -> byte[]]");
            console.log("Input (HEX): " + bytesToHex(input));
            console.log("Input (ASCII): " + bytesToString(input));
            
            const output = updateKey.call(this, input);

            if (output !== null) {
                console.log("Output (HEX): " + bytesToHex(output));
                console.log("Output (ASCII): " + bytesToString(output));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();

            return output;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Cipher.update(byte[] input, int inputOffset, int inputLen) -> byte[]]
        const updateKey = Cipher.update.overload(
            "[B",
            "int",
            "int"
        );

        updateKey.implementation = function (input, inputOffset, inputLen) {
            console.log("2. [Cipher.update(byte[] input, int inputOffset, int inputLen) -> byte[]]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen));
            
            const output = updateKey.call(this, input, inputOffset, inputLen);
            
            if (output !== null) {
                console.log("Output (HEX): " + bytesToHex(output));
                console.log("Output (ASCII): " + bytesToString(output));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();

            return output;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 3. [Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]
        const updateKey = Cipher.update.overload(
            "[B",
            "int",
            "int",
            "[B"
        );

        updateKey.implementation = function (input, inputOffset, inputLen, output) {
            console.log("3. [Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen));
            
            const outputLen = updateKey.call(this, input, inputOffset, inputLen, output);
            
            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output (HEX): " + bytesToHexRange(output, 0, outputLen));
                console.log("Output (ASCII): " + bytesToStringRange(output, 0, outputLen));
            } else {
                console.log("Output: <none>");
            
            }

            //traceStack();

            return outputLen;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 4. [Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]
        const updateKey = Cipher.update.overload(
            "[B",
            "int",
            "int",
            "[B",
            "int"
        );

        updateKey.implementation = function (input, inputOffset, inputLen, output, outputOffset) {
            console.log("4. [Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen));

            const outputLen = updateKey.call(this, input, inputOffset, inputLen, output, outputOffset);

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output offset: " + outputOffset);
                console.log("Output (HEX): " + bytesToHexRange(output, outputOffset, outputLen));
                console.log("Output (ASCII): " + bytesToStringRange(output, outputOffset, outputLen));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();
            
            return outputLen;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 5. [Cipher.update(ByteBuffer input, ByteBuffer output) -> int]
        const updateKey = Cipher.update.overload(
            "java.nio.ByteBuffer",
            "java.nio.ByteBuffer"
        );

        updateKey.implementation = function (input, output) {
            console.log("5. [Cipher.update(ByteBuffer input, ByteBuffer output) -> int]");
            
            console.log("Input buffer: " + input);
            
            //traceStack();

            const outputLen = updateKey.call(this, input, output);

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output buffer (HEX): " + bytesToHexRange(output, 0, outputLen));
                console.log("Output buffer (ASCII): " + bytesToStringRange(output, 0, outputLen));
            } else {
                console.log("Output: <none>");
            }

            return outputLen;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  --------------------------
    // | Cipher.doFinal overloads |
    //  --------------------------
    try { // 7. [Cipher.doFinal(ByteBuffer input, ByteBuffer output) -> int]
        const finalKey = Cipher.doFinal.overload(
            "java.nio.ByteBuffer",
            "java.nio.ByteBuffer"
        );

        finalKey.implementation = function (input, output) {
            console.log("7. [Cipher.doFinal(ByteBuffer input, ByteBuffer output) -> int]");
            
            console.log("Input buffer: " + input);
            console.log("Output buffer: " + output);
            
            //traceStack();

            const outputLen = finalKey.call(this, input, output);

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output buffer (HEX): " + bytesToHexRange(output, 0, outputLen));
                console.log("Output buffer (ASCII): " + bytesToStringRange(output, 0, outputLen));
            } else {
                console.log("Output: <none>");
            }

            return outputLen;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 1. [Cipher.doFinal() -> byte[]]
        const finalKey = Cipher.doFinal.overload();

        finalKey.implementation = function () {
            console.log("1. [Cipher.doFinal() -> byte[]]")

            const output = finalKey.call(this);

            if (result !== null) {
                console.log("Output (HEX): " + bytesToHex(output));
                console.log("Output (ASCII): " + bytesToString(output));
            } else {
                console.log("Output: <null>");
            }

            //traceStack();

            return output;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Cipher.doFinal(byte[] input) -> byte[]]
        const finalKey = Cipher.doFinal.overload(
            "[B"
        );

        finalKey.implementation = function (input) {
            console.log("2. [Cipher.doFinal(byte[] input) -> byte[]]")
            console.log("Input (HEX): " + bytesToHex(input));
            console.log("Input (ASCII): " + bytesToString(input));

            const output = finalKey.call(this, input);
            
            if (output !== null) {
                console.log("Output (HEX): " + bytesToHex(output));
                console.log("Output (ASCII): " + bytesToString(output));
            } else {
                console.log("Output: <null>");
            }
            
            //traceStack();

            return output;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 3. [Cipher.doFinal(byte[] output, int outputOffset) -> int]
        const finalKey = Cipher.doFinal.overload(
            "[B",
            "int"
        );

        finalKey.implementation = function (output, outputOffset) {
            console.log("3. [Cipher.doFinal(byte[] output, int outputOffset) -> int]");

            const outputLen = finalKey.call(this, output, outputOffset);
            
            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output (HEX): " + bytesToHexRange(output, outputOffset, outputLen));
                console.log("Output (ASCII): " + bytesToStringRange(output, outputOffset, outputLen));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();

            return outputLen;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 4. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen) -> byte[]]
        const finalKey = Cipher.doFinal.overload(
            "[B",
            "int",
            "int"
        );

        finalKey.implementation = function (input, inputOffset, inputLen) {
            console.log("4. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen) -> byte[]]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHex(input));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen));

            const output = finalKey.call(this, input, inputOffset, inputLen);
            
            if (output !== null) {
                console.log("Output (HEX): " + bytesToHex(output));
                console.log("Output (ASCII): " + bytesToString(output));
            } else {
                console.log("Output: <null>");
            }
            
            //traceStack();

            return output;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 5. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]
        const finalKey = Cipher.doFinal.overload();

        finalKey.implementation = function (input, inputOffset, inputLen, output) {
            console.log("5. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen));
        
            const outputLen = finalKey.call(this, input, inputOffset, inputLen, output);

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output (HEX): " + bytesToHexRange(output, 0, outputLen));
                console.log("Output (ASCII): " + bytesToStringRange(output, 0, outputLen));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();

            return outputLen;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 6. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]
        const finalKey = Cipher.doFinal.overload();

        finalKey.implementation = function (input, inputOffset, inputLen, output, outputOffset) {
            console.log("6. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHex(input));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen));
            
            const outputLen = finalKey.call(this, input, inputOffset, inputLen, output, outputOffset);

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output offset: " + outputOffset);
                console.log("Output (HEX): " + bytesToHexRange(output, outputOffset, outputLen));
                console.log("Output (ASCII): " + bytesToStringRange(output, outputOffset, outputLen));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();

            return outputLen;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }
    
    //  ------------------------------
    // | Cipher.getInstance overloads |
    //  ------------------------------
    try {// 1. [Cipher.getInstance(java.lang.String) -> static Cipher]
        const instanceKey = Cipher.getInstance.overload(
            "java.lang.String"
        );

        instanceKey.implementation = function(transformation) {
            console.log("1. [Cipher.getInstance(java.lang.String) -> static Cipher]")
            console.log("Requested transformation: " + transformation);

            const cipher = instanceKey.call(this, transformation);

            console.log("getAlgorithm(): " + cipher.getAlgorithm());
            console.log("Runtime class: " + cipher.getClass().getName());
            
            try {
                console.log("Block size: " + cipher.getBlockSize());
            } catch (e) {
                console.log("Error getting block size: " + e.message);
            }

            const provider = cipher.getProvider();
            if (provider !== null) {
                console.log("Provider name: " + provider.getName());
                console.log("Provider version: " + provider.getVersion());
                console.log("Provider info: " + provider.getInfo());
                console.log("Provider class: " + provider.getClass().getName());
            }

            return cipher;
        }
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Cipher.getInstance(java.lang.String, java.lang.String)] -> static Cipher
        const instanceKey = Cipher.getInstance.overload(
            "java.lang.String",
            "java.lang.String"
        );

        instanceKey.implementation = function (transformation, provider) {
            console.log("2. [Cipher.getInstance(java.lang.String, java.lang.String) -> static Cipher]")
            console.log("Requested transformation: " + transformation);
            console.log("Requested provider: " + provider);

            const cipher = instanceKey.call(this, transformation, provider);

            console.log("getAlgorithm(): " + cipher.getAlgorithm());
            console.log("Runtime class: " + cipher.getClass().getName());
            
            try {
                console.log("Block size: " + cipher.getBlockSize());
            } catch (e) {
                console.log("Error getting block size: " + e.message);
            }

            const cipherProvider = cipher.getProvider();
            if (provider !== null) {
                console.log("Provider name: " + cipherProvider.getName());
                console.log("Provider version: " + cipherProvider.getVersion());
                console.log("Provider info: " + cipherProvider.getInfo());
                console.log("Provider class: " + cipherProvider.getClass().getName());
            }

            return cipher;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 3. [Cipher.getInstance(java.lang.String, java.security.Provider) -> static Cipher]
        const instanceKey = Cipher.getInstance.overload(
            "java.lang.String",
            "java.security.Provider"
        );

        instanceKey.implementation = function (transformation, provider) {
            console.log("3. [Cipher.getInstance(java.lang.String, java.security.Provider) -> static Cipher]")
            console.log("Requested transformation: " + transformation);

            const cipher = instanceKey.call(this, transformation, provider);

            console.log("getAlgorithm(): " + cipher.getAlgorithm());
            console.log("Runtime class: " + cipher.getClass().getName());
            
            try {
                console.log("Block size: " + cipher.getBlockSize());
            } catch (e) {
                console.log("Error getting block size: " + e.message);
            }

            if (provider !== null) {
                console.log("Provider name: " + provider.getName());
                console.log("Provider version: " + provider.getVersion());
                console.log("Provider info: " + provider.getInfo());
                console.log("Provider class: " + provider.getClass().getName());
            }

            return cipher;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  ----------------------------
    // | Cipher.updateAAD overloads |
    //  ----------------------------
    try { // 1. [Cipher.updateAAD(byte[] src) -> void]
        const updateaadKey = Cipher.updateAAD.overload(
            "[B"
        );

        updateaadKey.implementation = function (src) {
            console.log("1. [Cipher.updateAAD(byte[] src) -> void]");
            console.log("Source bytes (HEX): " + bytesToHex(src));
            console.log("Source bytes (ASCII): " + bytesToString(src));

            const result = updateaadKey.call(this, src);
        };
    } catch(e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Cipher.updateAAD(byte[] src, int offset, int len) -> void]
        const updateaadKey = Cipher.updateAAD.overload(
            "[B",
            "int",
            "int"
        );

        updateaadKey.implementation = function (src, offset, len) {
            const aadSlice = byteArraySlice(src, offset, len);

            console.log("2. [Cipher.updateAAD(byte[] src, int offset, int len) -> void]")
            console.log("Source buffer (HEX): " + bytesToHex(src));
            console.log("Offset: " + offset);
            console.log("Length: " + len);
            console.log("AAD (HEX): " + bytesToHex(aadSlice));
            console.log("AAD (ASCII): " + bytesToString(aadSlice));

            const result = updateaadKey.call(this, src, offset, len);
        };
    } catch(e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 3. [Cipher.updateAAD(ByteBufer src) -> void]
        const updateaadKey = Cipher.updateAAD.overload(
            "java.nio.ByteBuffer"
        );

        updateaadKey.implementation = function (src) {
            console.log("3. [Cipher.updateAAD(ByteBufer src) -> void]");

            const positionBefore = src.position();
            const limitBefore = src.limit();
            const remainingBefore = src.remaining();

            console.log("Position before: " + positionBefore);
            console.log("Limit before: " + limitBefore);
            console.log("Remaining before: " + remainingBefore);

            // Duplicate shares content but maintains its own position/limit state.
            const duplicate = src.duplicate();

            const aad = Java.array(
                "byte",
                new Array(remainingBefore).fill(0) // New array of length remainingBefore, filled with 0s
            );

            duplicate.get(aad); // Copy bytes from duplicate to aad

            console.log("AAD (HEX): " + bytesToHex(aad));
            console.log("AAD (ASCII): " + bytesToString(aad));

            updateaadKey.call(this, src);

            console.log("Position after: " + src.position());
            console.log("Limit after: " + src.limit());
            console.log("Remaining after: " + src.remaining());
        };
    } catch(e) {
        console.log("[+] Error message: " + e.message);
    }
});