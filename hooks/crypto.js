'use strict';

let maxPrintableLength = 128; // Limit length of logged hex and ascii strings

function traceStack() {
    var stack = Java.use("java.lang.Exception").$new().getStackTrace();

    for (var i = 1; i < stack.length; i+= 1) {
        var element = stack[i];
        var className = element.getClassName();
        var methodName = element.getMethodName();
        var fileName = element.getFileName();
        var lineNumber = element.getLineNumber();

        console.log("" + className + "." + methodName + "; " + fileName + "." + lineNumber);
    }
}

function bytesToHex(bytes, maxLength) {
    if (bytes === null || bytes === undefined) {
        return "<null>";
    }

    let result = "";

    // A limit of 0 (or no limit) means the whole array. Never iterate past
    // the actual array length when the requested limit is larger than it.
    const hasLimit = typeof maxLength === "number" && maxLength > 0;
    const len = hasLimit ? Math.min(maxLength, bytes.length) : bytes.length;

    for (let i = 0; i < len; i++) {
        let v = bytes[i];

        if (v < 0)
            v += 256;

        result += ("0" + v.toString(16)).slice(-2);
    }

    if (hasLimit && bytes.length > len) {
        result += ` ... [${bytes.length - len} more bytes]`;
    }

    return result;
}

function bytesToHexRange(bytes, offset, length, maxLength) {
    let result = "";
    const end = Math.min(offset + length, bytes.length);

    // A limit of 0 (or no limit) means the whole array. Never iterate past
    // the actual array length when the requested limit is larger than it.
    const hasLimit = typeof maxLength === "number" && maxLength > 0;
    const len = hasLimit ? Math.min(maxLength, end) : end;

    for (let i = offset; i < len; i++) {
        let v = bytes[i];

        if (v < 0)
            v += 256;

        result += ("0" + v.toString(16)).slice(-2);
    }

    if (hasLimit && bytes.length > len) {
        result += ` ... [${bytes.length - len} more bytes]`;
    }

    return result;
}

function bytesToString(bytes, maxLength) {
    if (bytes === null || bytes === undefined) {
        return "<null>";
    }

    let result = '';

    // A limit of 0 (or no limit) means the whole array. Never iterate past
    // the actual array length when the requested limit is larger than it.
    const hasLimit = typeof maxLength === "number" && maxLength > 0;
    const len = hasLimit ? Math.min(maxLength, bytes.length) : bytes.length;

    for (let i = 0; i < len; ++i) {
        let val = bytes[i] & 0xFF;  // Get unsigned byte value
        // Only convert printable ASCII characters (32-126); otherwise, use a placeholder (.)
        if (val === 10) {
            result += "\\n";
        } else if (val === 13) {
            result += "\\r";
        } else if (val === 9) {
            result += "\\t";
        } else if (val >= 32 && val <= 126) {
            result += String.fromCharCode(val); // Convert only printable characters
        } else {
            result += '.';  // Replace non-printable characters with a dot
        }
    }

    if (hasLimit && bytes.length > len) {
        result += ` ... [${bytes.length - len} more bytes]`;
    }

    return result;
}

function bytesToStringRange(bytes, offset, length, maxLength) {
    let result = '';
    const end = Math.min(offset + length, bytes.length);

    // A limit of 0 (or no limit) means the whole array. Never iterate past
    // the actual array length when the requested limit is larger than it.
    const hasLimit = typeof maxLength === "number" && maxLength > 0;
    const len = hasLimit ? Math.min(maxLength, end) : end;

    for (let i = offset; i < len; ++i) {
        let val = bytes[i] & 0xFF;  // Get unsigned byte value
        // Only convert printable ASCII characters (32-126); otherwise, use a placeholder (.)
        if (val === 10) {
            result += "\\n";
        } else if (val === 13) {
            result += "\\r";
        } else if (val === 9) {
            result += "\\t";
        } else if (val >= 32 && val <= 126) {
            result += String.fromCharCode(val); // Convert only printable characters
        } else {
            result += '.';  // Replace non-printable characters with a dot
        }
    }

    if (hasLimit && bytes.length > len) {
        result += ` ... [${bytes.length - len} more bytes]`;
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
        console.log("Key bytes: " + bytesToHex(encoded, maxPrintableLength));
}

function logAlgorithmParameters(params) {
    if (params === null)
        return;

    console.log("Parameters class: " + params.$className);
    console.log("Parameters algorithm: " + params.getAlgorithm());

    try {
        console.log("Parameters encoded: " + bytesToHex(params.getEncoded(), maxPrintableLength));
    } catch (e) {
        console.log("Could not encode parameters: " + e);
    }
}

function logAlgorithmParameterSpec(params) {
    if (params === null)
        return;

    console.log("Parameter class: " + params.$className);

    if (params.$className === "javax.crypto.spec.IvParameterSpec") {
        const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        const ivSpec = Java.cast(params, IvParameterSpec);
        console.log("IV: " + bytesToHex(ivSpec.getIV(), maxPrintableLength));
    }

    if (params.$className === "javax.crypto.spec.GCMParameterSpec") {
        const GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
        const gcm = Java.cast(params, GCMParameterSpec);
        console.log("IV/nonce: " + bytesToHex(gcm.getIV(), maxPrintableLength));
        console.log("GCM tag bits: " + gcm.getTLen());
    }
}

function describeOpmode(opmode) {
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

function wrappedKeyTypeToString(type) {
    if (type === 1)
        return "PUBLIC_KEY";
    if (type === 2)
        return "PRIVATE_KEY";
    if (type === 3)
        return "SECRET_KEY";

    return "UNKNOWN(" + type + ")";
}

function base64FlagsToArray(flags) {
    const flagsToString = [];

    if (flags === 0)
        flagsToString.push("Default");
    if (flags & 1)
        flagsToString.push("NoPadding");
    if (flags & 2)
        flagsToString.push("NoWrap");
    if (flags & 4)
        flagsToString.push("Crlf");
    if (flags & 8)
        flagsToString.push("UrlSafe");
    if (flags & 16)
        flagsToString.push("NoClose");

    return flagsToString.values();
}

function base64FlagsToString(flags) {
    let string = "";
    for (const i of base64FlagsToArray(flags)) {
        if (string === "") {
            string = i; 
        } else {
            string = string + " " + i; 
        }
    }

    return string;
}

//  ------------
// | Main Logic |
//  ------------
Java.perform(function () {
    //  ------------------
    // | Cipher overloads |
    //  ------------------
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
            initKey.call(this, opmode, certificate);

            console.log("1. [Cipher.init(int opmode, Certificate certificate) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describeOpmode(opmode);

            console.log("Certificate type: " + certificate.getType());
            console.log("Public key: " + certificate.getPublicKey());

            traceStack();
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
            initKey.call(this, opmode, certificate, random);

            console.log("2. [Cipher.init(int opmode, Certificate certificate, SecureRandom random) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describeOpmode(opmode);

            console.log("Certificate type: " + certificate.getType());
            console.log("Public key: " + certificate.getPublicKey());
            console.log("SecureRandom: " + random);

            traceStack();
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
            initKey.call(this, opmode, key);

            console.log("3. [Cipher.init(int opmode, Key key) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describeOpmode(opmode);

            logKey(key);

            traceStack();
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
            initKey.call(this, opmode, key, params);

            console.log("4. [Cipher.init(int opmode, Key key, AlgorithmParameters params) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describeOpmode(opmode);

            logKey(key);
            logAlgorithmParameters(params);

            traceStack();
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
            initKey.call(this, opmode, key, params);

            console.log("5. [Cipher.init(int opmode, Key key, AlgorithmParameterSpec params) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describeOpmode(opmode);

            logKey(key);
            logAlgorithmParameterSpec(params);

            traceStack();
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
            initKey.call(this, opmode, key, params, random);

            console.log("6. [Cipher.init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describeOpmode(opmode);

            logKey(key);
            logAlgorithmParameterSpec(params);

            console.log("SecureRandom: " + random);

            traceStack();
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
            initKey.call(this, opmode, key, params, random);

            console.log("7. [Cipher.init(int opmode, Key key, AlgorithmParameters params, SecureRandom random) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describeOpmode(opmode);

            logKey(key);
            logAlgorithmParameters(params);

            console.log("SecureRandom: " + random);

            traceStack();
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
            initKey.call(this, opmode, key, random);

            console.log("8. [Cipher.init(int opmode, Key key, SecureRandom random) -> void]");
            console.log("Algorithm: " + this.getAlgorithm());
            describeOpmode(opmode);

            logKey(key);

            console.log("SecureRandom: " + random);

            traceStack();
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
            const output = updateKey.call(this, input);

            console.log("1. [Cipher.update(byte[] input) -> byte[]]");
            console.log("Input (HEX): " + bytesToHex(input, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToString(input, maxPrintableLength));

            if (output !== null) {
                console.log("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                console.log("Output (ASCII): " + bytesToString(output, maxPrintableLength));
            } else {
                console.log("Output: <none>");
            }

            traceStack();

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
            const output = updateKey.call(this, input, inputOffset, inputLen);

            console.log("2. [Cipher.update(byte[] input, int inputOffset, int inputLen) -> byte[]]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

            if (output !== null) {
                console.log("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                console.log("Output (ASCII): " + bytesToString(output, maxPrintableLength));
            } else {
                console.log("Output: <none>");
            }

            traceStack();

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
            const outputLen = updateKey.call(this, input, inputOffset, inputLen, output);

            console.log("3. [Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output (HEX): " + bytesToHexRange(output, 0, outputLen, maxPrintableLength));
                console.log("Output (ASCII): " + bytesToStringRange(output, 0, outputLen, maxPrintableLength));
            } else {
                console.log("Output: <none>");

            }

            traceStack();

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
            const outputLen = updateKey.call(this, input, inputOffset, inputLen, output, outputOffset);

            console.log("4. [Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output offset: " + outputOffset);
                console.log("Output (HEX): " + bytesToHexRange(output, outputOffset, outputLen, maxPrintableLength));
                console.log("Output (ASCII): " + bytesToStringRange(output, outputOffset, outputLen, maxPrintableLength));
            } else {
                console.log("Output: <none>");
            }

            traceStack();

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
            const outputLen = updateKey.call(this, input, output);

            console.log("5. [Cipher.update(ByteBuffer input, ByteBuffer output) -> int]");
            console.log("Input buffer: " + input);

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output buffer (HEX): " + bytesToHexRange(output, 0, outputLen, maxPrintableLength));
                console.log("Output buffer (ASCII): " + bytesToStringRange(output, 0, outputLen, maxPrintableLength));
            } else {
                console.log("Output: <none>");
            }

            traceStack();

            return outputLen;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  --------------------------
    // | Cipher.doFinal overloads |
    //  --------------------------
    try { // 1. [Cipher.doFinal() -> byte[]]
        const finalKey = Cipher.doFinal.overload();

        finalKey.implementation = function () {
            const output = finalKey.call(this);

            console.log("1. [Cipher.doFinal() -> byte[]]")

            if (result !== null) {
                console.log("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                console.log("Output (ASCII): " + bytesToString(output, maxPrintableLength));
            } else {
                console.log("Output: <null>");
            }

            traceStack();

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
            const output = finalKey.call(this, input);

            console.log("2. [Cipher.doFinal(byte[] input) -> byte[]]")
            console.log("Input (HEX): " + bytesToHex(input, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToString(input, maxPrintableLength));

            if (output !== null) {
                console.log("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                console.log("Output (ASCII): " + bytesToString(output, maxPrintableLength));
            } else {
                console.log("Output: <null>");
            }

            traceStack();

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
            const outputLen = finalKey.call(this, output, outputOffset);

            console.log("3. [Cipher.doFinal(byte[] output, int outputOffset) -> int]");

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output (HEX): " + bytesToHexRange(output, outputOffset, outputLen, maxPrintableLength));
                console.log("Output (ASCII): " + bytesToStringRange(output, outputOffset, outputLen, maxPrintableLength));
            } else {
                console.log("Output: <none>");
            }

            traceStack();

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
            const output = finalKey.call(this, input, inputOffset, inputLen);

            console.log("4. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen) -> byte[]]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

            if (output !== null) {
                console.log("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                console.log("Output (ASCII): " + bytesToString(output, maxPrintableLength));
            } else {
                console.log("Output: <null>");
            }

            traceStack();

            return output;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 5. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]
        const finalKey = Cipher.doFinal.overload();

        finalKey.implementation = function (input, inputOffset, inputLen, output) {
            const outputLen = finalKey.call(this, input, inputOffset, inputLen, output);

            console.log("5. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output (HEX): " + bytesToHexRange(output, 0, outputLen, maxPrintableLength));
                console.log("Output (ASCII): " + bytesToStringRange(output, 0, outputLen, maxPrintableLength));
            } else {
                console.log("Output: <none>");
            }

            traceStack();

            return outputLen;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 6. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]
        const finalKey = Cipher.doFinal.overload();

        finalKey.implementation = function (input, inputOffset, inputLen, output, outputOffset) {
            const outputLen = finalKey.call(this, input, inputOffset, inputLen, output, outputOffset);

            console.log("6. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]");
            console.log("Input offset: " + inputOffset);
            console.log("Input length: " + inputLen);
            console.log("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output offset: " + outputOffset);
                console.log("Output (HEX): " + bytesToHexRange(output, outputOffset, outputLen, maxPrintableLength));
                console.log("Output (ASCII): " + bytesToStringRange(output, outputOffset, outputLen, maxPrintableLength));
            } else {
                console.log("Output: <none>");
            }

            traceStack();

            return outputLen;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 7. [Cipher.doFinal(ByteBuffer input, ByteBuffer output) -> int]
        const finalKey = Cipher.doFinal.overload(
            "java.nio.ByteBuffer",
            "java.nio.ByteBuffer"
        );

        finalKey.implementation = function (input, output) {
            const outputLen = finalKey.call(this, input, output);

            console.log("7. [Cipher.doFinal(ByteBuffer input, ByteBuffer output) -> int]");

            console.log("Input buffer: " + input);
            console.log("Output buffer: " + output);

            if (outputLen > 0) {
                console.log("Bytes written: " + outputLen);
                console.log("Output buffer (HEX): " + bytesToHexRange(output, 0, outputLen, maxPrintableLength));
                console.log("Output buffer (ASCII): " + bytesToStringRange(output, 0, outputLen, maxPrintableLength));
            } else {
                console.log("Output: <none>");
            }

            traceStack();

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
            const cipher = instanceKey.call(this, transformation);

            console.log("1. [Cipher.getInstance(java.lang.String) -> static Cipher]")
            console.log("Requested transformation: " + transformation);

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

            traceStack();

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
            const cipher = instanceKey.call(this, transformation, provider);

            console.log("2. [Cipher.getInstance(java.lang.String, java.lang.String) -> static Cipher]")
            console.log("Requested transformation: " + transformation);
            console.log("Requested provider: " + provider);

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

            traceStack();

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
            const cipher = instanceKey.call(this, transformation, provider);

            console.log("3. [Cipher.getInstance(java.lang.String, java.security.Provider) -> static Cipher]")
            console.log("Requested transformation: " + transformation);

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

            traceStack();

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
            updateaadKey.call(this, src);

            console.log("1. [Cipher.updateAAD(byte[] src) -> void]");
            console.log("Source bytes (HEX): " + bytesToHex(src, maxPrintableLength));
            console.log("Source bytes (ASCII): " + bytesToString(src, maxPrintableLength));

            traceStack();
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
            updateaadKey.call(this, src, offset, len);

            const aadSlice = byteArraySlice(src, offset, len);

            console.log("2. [Cipher.updateAAD(byte[] src, int offset, int len) -> void]")
            console.log("Source buffer (HEX): " + bytesToHex(src, maxPrintableLength));
            console.log("Offset: " + offset);
            console.log("Length: " + len);
            console.log("AAD (HEX): " + bytesToHex(aadSlice, maxPrintableLength));
            console.log("AAD (ASCII): " + bytesToString(aadSlice, maxPrintableLength));

            traceStack();
        };
    } catch(e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 3. [Cipher.updateAAD(ByteBufer src) -> void]
        const updateaadKey = Cipher.updateAAD.overload(
            "java.nio.ByteBuffer"
        );

        updateaadKey.implementation = function (src) {
            const positionBefore = src.position();
            const limitBefore = src.limit();
            const remainingBefore = src.remaining();

            updateaadKey.call(this, src);

            console.log("3. [Cipher.updateAAD(ByteBufer src) -> void]");

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

            console.log("AAD (HEX): " + bytesToHex(aad, maxPrintableLength));
            console.log("AAD (ASCII): " + bytesToString(aad, maxPrintableLength));

            console.log("Position after: " + src.position());
            console.log("Limit after: " + src.limit());
            console.log("Remaining after: " + src.remaining());

            traceStack();
        };
    } catch(e) {
        console.log("[+] Error message: " + e.message);
    }

    //  -----------------------
    // | Cipher.wrap overloads |
    //  -----------------------
    try { // 1. [Cipher.wrap(java.security.Key) -> byte[]]
        const wrapKey = Cipher.wrap.overload(
            "java.security.Key"
        );

        wrapKey.implementation = function (key) {
            const wrappedKey = wrapKey.call(this, key);

            console.log("1. [Cipher.wrap(java.security.Key) -> byte[]]");
            console.log("Cipher transformation: " + this.getAlgorithm());

            logKey(key);

            console.log("Wrapped key (HEX): " + bytesToHex(wrappedKey, maxPrintableLength));

            traceStack();

            return wrappedKey;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  -------------------------
    // | Cipher.unwrap overloads |
    //  -------------------------
    try { // 1. [Cipher.unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) -> Key]
        const unwrapKey = Cipher.unwrap.overload(
            "[B",
            "java.lang.String",
            "int"
        );

        unwrapKey.implementation = function (wrappedKey, wrappedKeyAlgorithm, wrappedKeyType) {
            const unwrappedKey = unwrapKey.call(this, wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);

            console.log("1. [Cipher.unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) -> Key]");
            console.log("Cipher transformation: " + this.getAlgorithm());
            console.log("Wrapped key: " + bytesToHex(wrappedKey, maxPrintableLength));
            console.log("Wrapped key algorithm: " + wrappedKeyAlgorithm.toString());
            console.log("Wrapped key type: " + wrappedKeyTypeToString(wrappedKeyType) + " (" + wrappedKeyType + ")");

            logKey(unwrappedKey);

            traceStack();

            return unwrappedKey;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  ------------------
    // | Base64 overloads |
    //  ------------------
    const Base64 = Java.use("android.util.Base64");

    //  -------------------------
    // | Base64.encode overloads |
    //  -------------------------
    try { // 1. [Base64.encode(byte[] input, int flags) -> byte[]]
        const encodeKey = Base64.encode.overload(
            "[B",
            "int"
        );

        encodeKey.implementation = function(input, flags) {
            const encodedString = encodeKey.call(this, input, flags);

            let flagString = base64FlagsToString(flags);

            console.log("1. [Base64.encode(byte[] input, int flags) -> byte[]]");
            console.log("Input (HEX): " + bytesToHex(input, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToString(input, maxPrintableLength));
            console.log("Input length: " + input.length);
            console.log("Flags (Numerical): " + flags);
            console.log("Flags (String): " + flagString);

            console.log("Encoded string (HEX): " + bytesToHex(encodedString, maxPrintableLength));
            console.log("Encoded string (ASCII): " + bytesToString(encodedString, maxPrintableLength));
            console.log("Encoded string length: " + encodedString.length);

            //traceStack();

            return encodedString;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Base64.encode(byte[] input, int offset, int len, int flags) -> byte[]]
        const encodeKey = Base64.encode.overload(
            "[B",
            "int",
            "int",
            "int"
        );

        encodeKey.implementation = function(input, offset, len, flags) {
            const encodedString = encodeKey.call(this, input, offset, len, flags);

            let flagString = base64FlagsToString(flags);

            console.log("2. [Base64.encode(byte[input, int offset, int len, int flags]) -> byte[]]");
            console.log("Input (HEX): " + bytesToHexRange(input, offset, len, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToStringRange(input, offset, len, maxPrintableLength));
            console.log("Input length: " + input.length);
            console.log("Input offset: " + offset);
            console.log("Input length: " + len);
            console.log("Flags (Numerical): " + flags);
            console.log("Flags (String): " + flagString);

            console.log("Encoded string (HEX): " + bytesToHex(encodedString, maxPrintableLength));
            console.log("Encoded string (ASCII): " + bytesToString(encodedString, maxPrintableLength));
            console.log("Encoded string length: " + encodedString.length);

            //traceStack();

            return encodedString;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  ---------------------------------
    // | Base64.encodeToString overloads |
    //  ---------------------------------
    try { // 1. [Base64.encodeToString(byte[] input, int flags) -> java.lang.String]
        const encodeKey = Base64.encodeToString.overload(
            "[B",
            "int"
        );

        encodeKey.implementation = function(input, flags) {
            const encodedString = encodeKey.call(this, input, flags);

            let flagString = base64FlagsToString(flags);

            console.log("1. [Base64.encodeToString(byte[] input, int flags) -> java.lang.String]");
            console.log("Input (HEX): " + bytesToHex(input, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToString(input, maxPrintableLength));
            console.log("Input length: " + input.length);
            console.log("Flags (Numerical): " + flags);
            console.log("Flags (String): " + flagString);

            console.log("Encoded string: " + encodedString);
            console.log("Encoded string length: " + encodedString.length);

            //traceStack();

            return encodedString;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Base64.encodeToString(byte[] input, int offset, int len, int flags) -> java.lang.String]
        const encodeKey = Base64.encodeToString.overload(
            "[B",
            "int",
            "int",
            "int"
        );

        encodeKey.implementation = function(input, offset, len, flags) {
            const encodedString = encodeKey.call(this, input, offset, len, flags);

            let flagString = base64FlagsToString(flags);

            console.log("2. [Base64.encodeToString(byte[] input, int offset, int len, int flags]) -> java.lang.String]");
            console.log("Input (HEX): " + bytesToHexRange(input, offset, len, maxPrintableLength));
            console.log("Input (ASCII): " + bytesToStringRange(input, offset, len, maxPrintableLength));
            console.log("Input length: " + input.length);
            console.log("Input offset: " + offset);
            console.log("Input length: " + len);
            console.log("Flags (Numerical): " + flags);
            console.log("Flags (String): " + flagString);

            console.log("Encoded string: " + encodedString);
            console.log("Encoded string length: " + encodedString.length);

            //traceStack();

            return encodedString;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  -------------------------
    // | Base64.decode overloads |
    //  -------------------------
    try { // 1. [Base64.decode(java.lang.String str, int flags) -> byte[]
        const decodeKey = Base64.decode.overload(
            "java.lang.String",
            "int"
        );

        decodeKey.implementation = function (str, flags) {
            const decodedString = decodeKey.call(this, str, flags);

            let flagString = base64FlagsToString(flags);

            console.log("1. [Base64.decode(java.lang.String str, int flags) -> byte[]]");
            console.log("Encoded input: " + str);
            console.log("Flags (Numerical): " + flags);
            console.log("Flags (String): " + flagString);

            console.log("Decoded output (HEX): " + bytesToHex(decodedString, maxPrintableLength));
            console.log("Decoded output (ASCII): " + bytesToString(decodedString, maxPrintableLength));

            //traceStack();

            return decodedString;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Base64.decode(byte[] input, int flags) -> byte[]]
        const decodeKey = Base64.decode.overload(
            "[B",
            "int"
        );

        decodeKey.implementation = function (input, flags) {
            const decodedString = decodeKey.call(this, input, flags);

            let flagString = base64FlagsToString(flags);

            console.log("2. [Base64.decode(byte[] input, int flags) -> byte[]]");
            console.log("Encoded input (HEX): " + bytesToHex(input, maxPrintableLength));
            console.log("Encoded input (ASCII): " + bytesToString(input, maxPrintableLength));
            console.log("Flags (Numerical): " + flags);
            console.log("Flags (String): " + flagString);

            console.log("Decoded output (HEX): " + bytesToHex(decodedString, maxPrintableLength));
            console.log("Decoded output (ASCII): " + bytesToString(decodedString, maxPrintableLength));

            //traceStack();

            return decodedString;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 3. [Base64.decode(byte[] input, int offset, int len, int flags) -> byte[]]
        const decodeKey = Base64.decode.overload(
            "[B",
            "int",
            "int",
            "int"
        );

        decodeKey.implementation = function (input, offset, len, flags) {
            const decodedString = decodeKey.call(this, input, offset, len, flags);

            let flagString = base64FlagsToString(flags);

            console.log("3. [Base64.decode(byte[] input, int offset, int len, int flags) -> byte[]]");
            console.log("Encoded input (HEX): " + bytesToHexRange(input, offset, len, maxPrintableLength));
            console.log("Encoded input (ASCII): " + bytesToStringRange(input, offset, len, maxPrintableLength));
            console.log("Flags (Numerical): " + flags);
            console.log("Flags (String): " + flagString);

            console.log("Decoded output (HEX): " + bytesToHex(decodedString, maxPrintableLength));
            console.log("Decoded output (ASCII): " + bytesToString(decodedString, maxPrintableLength));

            //traceStack();

            return decodedString;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  -------------------------
    // | SecretKeySpec overloads |
    //  -------------------------
    const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

    //  -------------------------------
    // | SecretKeySpec.$init overloads |
    //  -------------------------------
    try { // 1. [SecretKeySpec.$init(byte[] key, String algorithm)] -> void
        const initKeySpec = SecretKeySpec.$init.overload(
            "[B",
            "java.lang.String"
        );

        initKeySpec.implementation = function (key, algorithm) {
            initKeySpec.call(this, key, algorithm);

            console.log("1. [SecretKeySpec.$init(byte[] key, String algorithm) -> void]");
            console.log("Key: " + bytesToHex(key, maxPrintableLength));
            console.log("Algorithm: " + algorithm);

            console.log("getAlgorithm(): " + this.getAlgorithm());
            console.log("getFormat(): " + this.getFormat());

            const encoded = this.getEncoded();
            console.log("getEncoded() length: " + encoded.length);

            traceStack();
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [SecretKeySpec.$init(byte[] key, int offset, int len, String algorithm) -> void]
        const initKeySpec = SecretKeySpec.$init.overload(
            "[B",
            "int",
            "int",
            "java.lang.String"
        );

        initKeySpec.implementation = function (key, offset, len, algorithm) {
            initKeySpec.call(this, key, offset, len, algorithm);

            console.log("2. [SecretKeySpec.$init(byte[] key, int offset, int len, String algorithm) -> void]");
            console.log("Key: " + bytesToHex(key, maxPrintableLength));
            console.log("Offset: " + offset);
            console.log("Length: " + len);
            console.log("Algorithm: " + algorithm);

            console.log("getAlgorithm(): " + this.getAlgorithm());
            console.log("getFormat(): " + this.getFormat());

            const encoded = this.getEncoded();
            console.log("getEncoded() length: " + encoded.length);

            traceStack();
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  ---------------------------
    // | IvParameterSpec overloads |
    //  ---------------------------
    const IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');

    //  ---------------------------------
    // | IvParameterSpec.$init overloads |
    //  ---------------------------------
    try { // 1. [IvParameterSpec(byte[] iv) -> void]
        const initIvKey = IvParameterSpec.$init.overload(
            "[B"
        );

        initIvKey.implementation = function (iv) {
            initIvKey.call(this, iv);

            console.log("1. [IvParameterSpec(byte[] iv) -> void]");
            console.log("IV: " + bytesToHex(iv, maxPrintableLength));

            const storedIv = this.getIV();

            console.log("Constructed IV length: " + storedIv.length);
            console.log("Constructed IV: " + bytesToHex(storedIv, maxPrintableLength));

            traceStack();
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [IvParameterSpec(byte[] iv, int offset, int len) -> void]
        const initIvKey = IvParameterSpec.$init.overload(
            "[B",
            "int",
            "int"
        );

        initIvKey.implementation = function (iv, offset, len) {
            initIvKey.call(this, iv, offset, len);

            console.log("2. [IvParameterSpec(byte[] iv, int offset, int len) -> void]");
            console.log("IV: " + bytesToHex(iv, maxPrintableLength));
            console.log("Offset: " + offset);
            console.log("Length: " + len);

            const storedIv = this.getIV();

            console.log("Constructed IV length: " + storedIv.length);
            console.log("Constructed IV: " + bytesToHexRange(storedIv, offset, len, maxPrintableLength));

            traceStack();
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }
});
