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

Java.perform(function () {
    const Cipher = Java.use("javax.crypto.Cipher");

    //  -----------------------
    // | Cipher.init overloads |
    //  -----------------------
    try { // 1. [Cipher.init(int, Key)]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key"
        );

        initKey.implementation = function (opmode, key) {
            console.log("1. [Cipher.init(int, Key)]");
            console.log("Algorithm: " + this.getAlgorithm());
            describe_opmode(opmode);

            logKey(key);

            //traceStack();

            return initKey.call(this, opmode, key);
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Cipher.init(int, Key, AlgorithmParameters)]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key",
            "java.security.AlgorithmParameters"
        );

        initKey.implementation = function (opmode, key, params) {
            console.log("2. [Cipher.init(int, Key, AlgorithmParameters)]");
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

    try { // 3. [Cipher.init(int, Key, AlgorithmParameters, SecureRandom)]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key",
            "java.security.AlgorithmParameters",
            "java.security.SecureRandom"
        );

        initKey.implementation = function (opmode, key, params, random) {
            console.log("3. [Cipher.init(int, Key, AlgorithmParameters, SecureRandom)]");
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

    try { // 4. [Cipher.init(int, Key, SecureRandom)]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key",
            "java.security.SecureRandom"
        );

        initKey.implementation = function (opmode, key, random) {
            console.log("4. [Cipher.init(int, Key, SecureRandom)]");
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

    try { // 5. [Cipher.init(int, Key, AlgorithmParameterSpec)]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key",
            "java.security.spec.AlgorithmParameterSpec"
        );

        initKey.implementation = function (opmode, key, params) {
            console.log("5. [Cipher.init(int, Key, AlgorithmParameterSpec)]");
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

    try { // 6. [Cipher.init(int, Key, AlgorithmParameterSpec, SecureRandom)]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.Key",
            "java.security.spec.AlgorithmParameterSpec",
            "java.security.SecureRandom"
        );

        initKey.implementation = function (opmode, key, params, random) {
            console.log("6. [Cipher.init(int, Key, AlgorithmParameterSpec, SecureRandom)]");
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

    try { // 7. [Cipher.init(int, Certificate)]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.cert.Certificate"
        );

        initKey.implementation = function (opmode, certificate) {
            console.log("7. [Cipher.init(int, Certificate)]");
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

    try { // 8. [Cipher.init(int, Certificate, SecureRandom)]
        const initKey = Cipher.init.overload(
            "int",
            "java.security.cert.Certificate",
            "java.security.SecureRandom"
        );

        initKey.implementation = function (opmode, certificate, random) {
            console.log("8. [Cipher.init(int, Certificate, SecureRandom)]");
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

    //  -------------------------
    // | Cipher.update overloads |
    //  -------------------------
    try { // 1. [Cipher.update(ByteBuffer, ByteBuffer)]
        const updateKey = Cipher.update.overload(
            "java.nio.ByteBuffer",
            "java.nio.ByteBuffer"
        );

        updateKey.implementation = function (inputBuf, outputBuf) {
            console.log("1. [Cipher.update(ByteBuffer, ByteBuffer)]");
            
            console.log("Input buffer: " + inputBuf);
            console.log("Output buffer: " + outputBuf);
            
            //traceStack();

            const result = updateKey.call(this, inputBuf, outputBuf);

            return result;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Cipher.update([B, int, int, [B)]
        const updateKey = Cipher.update.overload(
            "[B",
            "int",
            "int",
            "[B"
        );

        updateKey.implementation = function (input, inputOffset, inputLength, output) {
            console.log("2. [Cipher.update([B, int, int, [B)]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLength);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLength));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLength));
            
            const outputLength = updateKey.call(this, input, inputOffset, inputLength, output);
            console.log("Bytes written: " + outputLength);
            
            if (outputLength > 0) {
                console.log("Output offset: " + outputOffset);
                console.log("Output (HEX): " + bytesToHexRange(output, 0, outputLength));
                console.log("Output (ASCII): " + bytesToStringRange(output, 0, outputLength));
            } else {
                console.log("Output: <none>");
            
            }

            //traceStack();

            return outputLength;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 3. [Cipher.update([B, int, int, [B, int)]
        const updateKey = Cipher.update.overload(
            "[B",
            "int",
            "int",
            "[B",
            "int"
        );

        updateKey.implementation = function (input, inputOffset, inputLength, output, outputOffset) {
            console.log("3. [Cipher.update([B, int, int, [B, int)]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLength);
            console.log("Input (HEX): " + bytesToHex(input, inputOffset, inputLength));
            console.log("Input (ASCII): " + bytesToString(input, inputOffset, inputLength));

            const outputLength = updateKey.call(this, input, inputOffset, inputLength, output, outputOffset);

            if (outputLength > 0) {
                console.log("Bytes written: " + outputLength);
                console.log("Output offset: " + outputOffset);
                console.log("Output (HEX): " + bytesToHexRange(output, outputOffset, outputLength));
                console.log("Output (ASCII): " + bytesToStringRange(output, outputOffset, outputLength));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();
            
            return outputLength;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 4. [Cipher.update([B)]
        const updateKey = Cipher.update.overload(
            "[B"
        );

        updateKey.implementation = function (input) {
            console.log("4. [Cipher.update([B)]");
            console.log("Input (HEX): " + bytesToHex(input));
            console.log("Input (ASCII): " + bytesToString(input));
            
            const result = updateKey.call(this, input);

            if (result !== null) {
                console.log("Output (HEX): " + bytesToHex(result));
                console.log("Output (ASCII): " + bytesToString(result));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();

            return result;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 5. [Cipher.update([B, int, int)
        const updateKey = Cipher.update.overload(
            "[B",
            "int",
            "int"
        );

        updateKey.implementation = function (input, inputOffset, inputLength) {
            console.log("5. [Cipher.update([B, int, int)]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLength);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLength));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLength));
            
            const result = updateKey.call(this, input, inputOffset, inputLength);
            
            if (outputLength !== null) {
                console.log("Output (HEX): " + bytesToHex(result));
                console.log("Output (ASCII): " + bytesToString(result));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();

            return result;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  --------------------------
    // | Cipher.doFinal overloads |
    //  --------------------------
    try { // 1. [Cipher.doFinal(ByteBuffer, ByteBuffer)]
        const finalKey = Cipher.doFinal.overload(
            "java.nio.ByteBuffer",
            "java.nio.ByteBuffer"
        );

        finalKey.implementation = function (inputBuf, outputBuf) {
            console.log("1. [Cipher.doFinal(ByteBuffer, ByteBuffer)]");
            
            console.log("Input buffer: " + inputBuf);
            console.log("Output buffer: " + outputBuf);
            
            //traceStack();

            const result = finalKey.call(this, inputBuf, outputBuf);

            return result;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Cipher.doFinal()]
        const finalKey = Cipher.doFinal.overload();

        finalKey.implementation = function () {
            console.log("2. [Cipher.doFinal()]")

            const result = finalKey.call(this);
            if (result !== null) {
                console.log("Output (HEX): " + bytesToHex(result));
                console.log("Output (ASCII): " + bytesToString(result));
            } else {
                console.log("Output: <null>");
            }

            //traceStack();

            return result;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 3. [Cipher.doFinal([B)]
        const finalKey = Cipher.doFinal.overload(
            "[B"
        );

        finalKey.implementation = function (input) {
            console.log("3. [Cipher.doFinal([B)]")
            console.log("Input (HEX): " + bytesToHex(input));
            console.log("Input (ASCII): " + bytesToString(input));

            const result = finalKey.call(this, input);
            if (result !== null) {
                console.log("Output (HEX): " + bytesToHex(result));
                console.log("Output (ASCII): " + bytesToString(result));
            } else {
                console.log("Output: <null>");
            }
            
            //traceStack();

            return result;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 4. [Cipher.doFinal([B, int])]
        const finalKey = Cipher.doFinal.overload(
            "[B",
            "int"
        );

        finalKey.implementation = function (output, outputOffset) {
            console.log("4. [Cipher.doFinal([B, int])]");

            const outputLength = finalKey.call(this, output, outputOffset);
            
            if (outputLength > 0) {
                console.log("Bytes written: " + outputLength);
                console.log("Output (HEX): " + bytesToHexRange(output, 0, outputLength));
                console.log("Output (ASCII): " + bytesToStringRange(output, 0, outputLength));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();

            return outputLength;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 5. [Cipher.doFinal([B, int, int)]
        const finalKey = Cipher.doFinal.overload(
            "[B",
            "int",
            "int"
        );

        finalKey.implementation = function (input, inputOffset, inputLength) {
            console.log("5. [Cipher.doFinal([B, int, int)]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLength);
            console.log("Input (HEX): " + bytesToHex(input));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLength));

            const result = finalKey.call(this, input, inputOffset, inputLength);
            
            if (result !== null) {
                console.log("Output (HEX): " + bytesToHex(result));
                console.log("Output (ASCII): " + bytesToString(result));
            } else {
                console.log("Output: <null>");
            }
            
            //traceStack();

            return result;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 6. [Cipher.doFinal([B, int, int, [B)]
        const finalKey = Cipher.doFinal.overload();

        finalKey.implementation = function (input, inputOffset, inputLength, output) {
            console.log("6. [Cipher.doFinal([B, int, int, [B)]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLength);
            console.log("Input (HEX): " + bytesToHex(input));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLength));
        
            const outputLength = finalKey.call(this, input, inputOffset, inputLength, output);

            if (outputLength > 0) {
                console.log("Bytes written: " + outputLength);
                console.log("Output (HEX): " + bytesToHexRange(output, 0, outputLength));
                console.log("Output (ASCII): " + bytesToStringRange(output, 0, outputLength));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();

            return outputLength;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 7. [Cipher.doFinal([B, int, int, [B, int)]
        const finalKey = Cipher.doFinal.overload();

        finalKey.implementation = function (input, inputOffset, inputLength, output, outputOffset) {
            console.log("7. [Cipher.doFinal([B, int, int, [B, int)]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLength);
            console.log("Input (HEX): " + bytesToHex(input));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLength));
            
            const outputLength = finalKey.call(this, input, inputOffset, inputLength, output, outputOffset);
            console.log("Bytes written: " + outputLength);

            if (outputLength > 0) {
                console.log("Output offset: " + outputOffset);
                console.log("Output: " + bytesToHexRange(output, outputOffset, outputLength));
            } else {
                console.log("Output: <none>");
            }

            //traceStack();

            return outputLength;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }
});