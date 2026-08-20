'use strict';

const maxPrintableLength = 128; // Limit length of logged hex and ascii strings
const Log = Java.use("android.util.Log");
const Throwable = Java.use("java.lang.Throwable");

function traceStack() {
    const stack = Log.getStackTraceString(Throwable.$new());
    return "Stack:\n\t" + stack;
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

    // A limit of 0 (or no limit) means the whole array. Never iterate past
    // the actual array length when the requested limit is larger than it.
    const hasLimit = typeof maxLength === "number" && maxLength > 0;
    const len = hasLimit ? Math.min(maxLength, length) : length;

    for (let i = offset; i < (offset + len); i++) {
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

    // A limit of 0 (or no limit) means the whole array. Never iterate past
    // the actual array length when the requested limit is larger than it.
    const hasLimit = typeof maxLength === "number" && maxLength > 0;
    const len = hasLimit ? Math.min(maxLength, length) : length;

    for (let i = offset; i < (offset + len); ++i) {
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

    let log = "";

    log += "Key class: " + key.$className + "\n";
    log += "Key algorithm: " + key.getAlgorithm() + "\n";
    log += "Key format: " + key.getFormat() + "\n";

    const encoded = key.getEncoded();

    if (encoded !== null)
        log += "Key bytes: " + bytesToHex(encoded, maxPrintableLength);

    return log;
}

function logAlgorithmParameters(params) {
    if (params === null)
        return;

    let log = "";

    log += "Parameters class: " + params.$className + "\n";
    log += "Parameters algorithm: " + params.getAlgorithm() + "\n";

    try {
        log += "Parameters encoded: " + bytesToHex(params.getEncoded(), maxPrintableLength);
    } catch (e) {
        log += "Could not encode parameters: " + e.message;
    }

    return log;
}

function logAlgorithmParameterSpec(params) {
    if (params === null)
        return;

    let log = "";

    log += "Parameter class: " + params.$className + "\n";

    if (params.$className === "javax.crypto.spec.IvParameterSpec") {
        const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        const ivSpec = Java.cast(params, IvParameterSpec);
        log += "IV: " + bytesToHex(ivSpec.getIV(), maxPrintableLength);
    }

    if (params.$className === "javax.crypto.spec.GCMParameterSpec") {
        const GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
        const gcm = Java.cast(params, GCMParameterSpec);
        log += "IV/nonce: " + bytesToHex(gcm.getIV(), maxPrintableLength) + "\n";
        log += "GCM tag bits: " + gcm.getTLen();
    }

    return log;
}

function describeOpmode(opmode) {
    if (opmode === 1) {
        return "opmode: " + opmode + " (ENCRYPT)";
    } else if (opmode === 2) {
        return "opmode: " + opmode + " (DECRYPT)";
    } else if (opmode === 3) {
        return "opmode: " + opmode + " (UNWRAP)";
    } else if (opmode === 4) {
        return "opmode: " + opmode + " (WRAP)";
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
setTimeout(function () {
    Java.perform(function () {
        //  ------------------
        // | Cipher overloads |
        //  ------------------
        const Cipher = Java.use("javax.crypto.Cipher");
        
        //  ------------------------------
        // | Cipher.getInstance overloads |
        //  ------------------------------
        try {// 1. [Cipher.getInstance(java.lang.String) -> static Cipher]
            const instanceKey = Cipher.getInstance.overload(
                "java.lang.String"
            );

            instanceKey.implementation = function (transformation) {
                const cipher = instanceKey.call(Cipher, transformation);
                const lines = [];

                lines.push("1. [Cipher.getInstance(java.lang.String) -> static Cipher]")
                lines.push("Requested transformation: " + transformation);

                lines.push("getAlgorithm(): " + cipher.getAlgorithm());
                lines.push("Runtime class: " + cipher.getClass().getName());

                try {
                    lines.push("Block size: " + cipher.getBlockSize());
                } catch (e) {
                    lines.push("Error getting block size: " + e.message);
                }

                const provider = cipher.getProvider();
                if (provider !== null) {
                    lines.push("Provider name: " + provider.getName());
                    lines.push("Provider version: " + provider.getVersion());
                    lines.push("Provider info: " + provider.getInfo());
                    lines.push("Provider class: " + provider.getClass().getName());
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return cipher;
            }
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 2. [Cipher.getInstance(java.lang.String, java.lang.String) -> static Cipher]
            const instanceKey = Cipher.getInstance.overload(
                "java.lang.String",
                "java.lang.String"
            );

            instanceKey.implementation = function (transformation, provider) {
                const cipher = instanceKey.call(Cipher, transformation, provider);
                const lines = [];

                lines.push("2. [Cipher.getInstance(java.lang.String, java.lang.String) -> static Cipher]")
                lines.push("Requested transformation: " + transformation);
                lines.push("Requested provider: " + provider);

                lines.push("getAlgorithm(): " + cipher.getAlgorithm());
                lines.push("Runtime class: " + cipher.getClass().getName());

                try {
                    lines.push("Block size: " + cipher.getBlockSize());
                } catch (e) {
                    lines.push("Error getting block size: " + e.message);
                }

                const cipherProvider = cipher.getProvider();
                if (provider !== null) {
                    lines.push("Provider name: " + cipherProvider.getName());
                    lines.push("Provider version: " + cipherProvider.getVersion());
                    lines.push("Provider info: " + cipherProvider.getInfo());
                    lines.push("Provider class: " + cipherProvider.getClass().getName());
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const cipher = instanceKey.call(Cipher, transformation, provider);
                const lines = [];

                lines.push("3. [Cipher.getInstance(java.lang.String, java.security.Provider) -> static Cipher]")
                lines.push("Requested transformation: " + transformation);

                lines.push("getAlgorithm(): " + cipher.getAlgorithm());
                lines.push("Runtime class: " + cipher.getClass().getName());

                try {
                    lines.push("Block size: " + cipher.getBlockSize());
                } catch (e) {
                    lines.push("Error getting block size: " + e.message);
                }

                if (provider !== null) {
                    lines.push("Provider name: " + provider.getName());
                    lines.push("Provider version: " + provider.getVersion());
                    lines.push("Provider info: " + provider.getInfo());
                    lines.push("Provider class: " + provider.getClass().getName());
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return cipher;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

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

                const lines = [];

                lines.push("1. [Cipher.init(int opmode, Certificate certificate) -> void]");
                lines.push("Algorithm: " + this.getAlgorithm());
                lines.push(describeOpmode(opmode));

                lines.push("Certificate type: " + certificate.getType());
                lines.push("Public key: " + certificate.getPublicKey());

                //lines.push(traceStack());

                console.log(lines.join("\n"));
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
                const lines = [];

                initKey.call(this, opmode, certificate, random);

                lines.push("2. [Cipher.init(int opmode, Certificate certificate, SecureRandom random) -> void]");
                lines.push("Algorithm: " + this.getAlgorithm());
                lines.push(describeOpmode(opmode));

                lines.push("Certificate type: " + certificate.getType());
                lines.push("Public key: " + certificate.getPublicKey());
                lines.push("SecureRandom: " + random);

                //lines.push(traceStack());

                console.log(lines.join("\n"));
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
                const lines = [];

                initKey.call(this, opmode, key);

                lines.push("3. [Cipher.init(int opmode, Key key) -> void]");
                lines.push("Algorithm: " + this.getAlgorithm());
                lines.push(describeOpmode(opmode));

                lines.push(logKey(key));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
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
                const lines = [];

                initKey.call(this, opmode, key, params);

                lines.push("4. [Cipher.init(int opmode, Key key, AlgorithmParameters params) -> void]");
                lines.push("Algorithm: " + this.getAlgorithm());
                lines.push(describeOpmode(opmode));

                lines.push(logKey(key));
                lines.push(logAlgorithmParameters(params));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
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
                const lines = [];

                initKey.call(this, opmode, key, params);

                lines.push("5. [Cipher.init(int opmode, Key key, AlgorithmParameterSpec params) -> void]");
                lines.push("Algorithm: " + this.getAlgorithm());
                lines.push(describeOpmode(opmode));

                lines.push(logKey(key));
                lines.push(logAlgorithmParameterSpec(params));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
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
                const lines = [];

                initKey.call(this, opmode, key, params, random);

                lines.push("6. [Cipher.init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) -> void]");
                lines.push("Algorithm: " + this.getAlgorithm());
                lines.push(describeOpmode(opmode));

                lines.push(logKey(key));
                lines.push(logAlgorithmParameterSpec(params));

                lines.push("SecureRandom: " + random);

                //lines.push(traceStack());

                console.log(lines.join("\n"));
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
                const lines = [];

                initKey.call(this, opmode, key, params, random);

                lines.push("7. [Cipher.init(int opmode, Key key, AlgorithmParameters params, SecureRandom random) -> void]");
                lines.push("Algorithm: " + this.getAlgorithm());
                lines.push(describeOpmode(opmode));

                lines.push(logKey(key));
                lines.push(logAlgorithmParameters(params));

                lines.push("SecureRandom: " + random);

                //lines.push(traceStack());

                console.log(lines.join("\n"));
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
                const lines = [];

                initKey.call(this, opmode, key, random);

                lines.push("8. [Cipher.init(int opmode, Key key, SecureRandom random) -> void]");
                lines.push("Algorithm: " + this.getAlgorithm());
                lines.push(describeOpmode(opmode));

                lines.push(logKey(key));

                lines.push("SecureRandom: " + random);

                //lines.push(traceStack());

                console.log(lines.join("\n"));
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
                const lines = [];

                lines.push("1. [Cipher.update(byte[] input) -> byte[]]");
                lines.push("Input (HEX): " + bytesToHex(input, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToString(input, maxPrintableLength));

                if (output !== null) {
                    lines.push("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToString(output, maxPrintableLength));
                } else {
                    lines.push("Output: <none>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("2. [Cipher.update(byte[] input, int inputOffset, int inputLen) -> byte[]]");
                lines.push("Input offset: " + inputOffset);
                lines.push("Input length: " + inputLen);
                lines.push("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

                if (output !== null) {
                    lines.push("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToString(output, maxPrintableLength));
                } else {
                    lines.push("Output: <none>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("3. [Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]");
                lines.push("Input offset: " + inputOffset);
                lines.push("Input length: " + inputLen);
                lines.push("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

                if (outputLen > 0) {
                    lines.push("Bytes written: " + outputLen);
                    lines.push("Output (HEX): " + bytesToHexRange(output, 0, outputLen, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToStringRange(output, 0, outputLen, maxPrintableLength));
                } else {
                    lines.push("Output: <none>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("4. [Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]");
                lines.push("Input offset: " + inputOffset);
                lines.push("Input length: " + inputLen);
                lines.push("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

                if (outputLen > 0) {
                    lines.push("Bytes written: " + outputLen);
                    lines.push("Output offset: " + outputOffset);
                    lines.push("Output (HEX): " + bytesToHexRange(output, outputOffset, outputLen, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToStringRange(output, outputOffset, outputLen, maxPrintableLength));
                } else {
                    lines.push("Output: <none>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("5. [Cipher.update(ByteBuffer input, ByteBuffer output) -> int]");
                lines.push("Input buffer: " + input);

                if (outputLen > 0) {
                    lines.push("Bytes written: " + outputLen);
                    lines.push("Output buffer (HEX): " + bytesToHexRange(output, 0, outputLen, maxPrintableLength));
                    lines.push("Output buffer (ASCII): " + bytesToStringRange(output, 0, outputLen, maxPrintableLength));
                } else {
                    lines.push("Output: <none>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("1. [Cipher.doFinal() -> byte[]]")

                if (output !== null) {
                    lines.push("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToString(output, maxPrintableLength));
                } else {
                    lines.push("Output: <null>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("2. [Cipher.doFinal(byte[] input) -> byte[]]")
                lines.push("Input (HEX): " + bytesToHex(input, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToString(input, maxPrintableLength));

                if (output !== null) {
                    lines.push("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToString(output, maxPrintableLength));
                } else {
                    lines.push("Output: <null>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("3. [Cipher.doFinal(byte[] output, int outputOffset) -> int]");

                if (outputLen > 0) {
                    lines.push("Bytes written: " + outputLen);
                    lines.push("Output (HEX): " + bytesToHexRange(output, outputOffset, outputLen, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToStringRange(output, outputOffset, outputLen, maxPrintableLength));
                } else {
                    lines.push("Output: <none>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("4. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen) -> byte[]]");
                lines.push("Input offset: " + inputOffset);
                lines.push("Input length: " + inputLen);
                lines.push("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

                if (output !== null) {
                    lines.push("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToString(output, maxPrintableLength));
                } else {
                    lines.push("Output: <null>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return output;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 5. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]
            const finalKey = Cipher.doFinal.overload(
                "[B",
                "int",
                "int",
                "[B"
            );

            finalKey.implementation = function (input, inputOffset, inputLen, output) {
                const outputLen = finalKey.call(this, input, inputOffset, inputLen, output);
                const lines = [];

                lines.push("5. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]");
                lines.push("Input offset: " + inputOffset);
                lines.push("Input length: " + inputLen);
                lines.push("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

                if (outputLen > 0) {
                    lines.push("Bytes written: " + outputLen);
                    lines.push("Output (HEX): " + bytesToHexRange(output, 0, outputLen, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToStringRange(output, 0, outputLen, maxPrintableLength));
                } else {
                    lines.push("Output: <none>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return outputLen;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 6. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]
            const finalKey = Cipher.doFinal.overload(
                "[B",
                "int",
                "int",
                "[B",
                "int"
            );

            finalKey.implementation = function (input, inputOffset, inputLen, output, outputOffset) {
                const outputLen = finalKey.call(this, input, inputOffset, inputLen, output, outputOffset);
                const lines = [];

                lines.push("6. [Cipher.doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]");
                lines.push("Input offset: " + inputOffset);
                lines.push("Input length: " + inputLen);
                lines.push("Input (HEX): " + bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength));

                if (outputLen > 0) {
                    lines.push("Bytes written: " + outputLen);
                    lines.push("Output offset: " + outputOffset);
                    lines.push("Output (HEX): " + bytesToHexRange(output, outputOffset, outputLen, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToStringRange(output, outputOffset, outputLen, maxPrintableLength));
                } else {
                    lines.push("Output: <none>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("7. [Cipher.doFinal(ByteBuffer input, ByteBuffer output) -> int]");

                lines.push("Input buffer: " + input);
                lines.push("Output buffer: " + output);

                if (outputLen > 0) {
                    lines.push("Bytes written: " + outputLen);
                    lines.push("Output buffer (HEX): " + bytesToHexRange(output, 0, outputLen, maxPrintableLength));
                    lines.push("Output buffer (ASCII): " + bytesToStringRange(output, 0, outputLen, maxPrintableLength));
                } else {
                    lines.push("Output: <none>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return outputLen;
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
                const lines = [];

                lines.push("1. [Cipher.updateAAD(byte[] src) -> void]");
                lines.push("Source bytes (HEX): " + bytesToHex(src, maxPrintableLength));
                lines.push("Source bytes (ASCII): " + bytesToString(src, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
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
                const lines = [];

                const aadSlice = byteArraySlice(src, offset, len);

                lines.push("2. [Cipher.updateAAD(byte[] src, int offset, int len) -> void]")
                lines.push("Source buffer (HEX): " + bytesToHex(src, maxPrintableLength));
                lines.push("Offset: " + offset);
                lines.push("Length: " + len);
                lines.push("AAD (HEX): " + bytesToHex(aadSlice, maxPrintableLength));
                lines.push("AAD (ASCII): " + bytesToString(aadSlice, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 3. [Cipher.updateAAD(ByteBufer src) -> void]
            const updateaadKey = Cipher.updateAAD.overload(
                "java.nio.ByteBuffer"
            );

            updateaadKey.implementation = function (src) {
                const lines = [];
                const positionBefore = src.position();
                const limitBefore = src.limit();
                const remainingBefore = src.remaining();

                updateaadKey.call(this, src);

                lines.push("3. [Cipher.updateAAD(ByteBufer src) -> void]");

                lines.push("Position before: " + positionBefore);
                lines.push("Limit before: " + limitBefore);
                lines.push("Remaining before: " + remainingBefore);

                // Duplicate shares content but maintains its own position/limit state.
                const duplicate = src.duplicate();

                const aad = Java.array(
                    "byte",
                    new Array(remainingBefore).fill(0) // New array of length remainingBefore, filled with 0s
                );

                duplicate.get(aad); // Copy bytes from duplicate to aad

                lines.push("AAD (HEX): " + bytesToHex(aad, maxPrintableLength));
                lines.push("AAD (ASCII): " + bytesToString(aad, maxPrintableLength));

                lines.push("Position after: " + src.position());
                lines.push("Limit after: " + src.limit());
                lines.push("Remaining after: " + src.remaining());

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
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
                const lines = [];

                lines.push("1. [Cipher.wrap(java.security.Key) -> byte[]]");
                lines.push("Cipher transformation: " + this.getAlgorithm());

                logKey(key);

                lines.push("Wrapped key (HEX): " + bytesToHex(wrappedKey, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("1. [Cipher.unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) -> Key]");
                lines.push("Cipher transformation: " + this.getAlgorithm());
                lines.push("Wrapped key: " + bytesToHex(wrappedKey, maxPrintableLength));
                lines.push("Wrapped key algorithm: " + wrappedKeyAlgorithm.toString());
                lines.push("Wrapped key type: " + wrappedKeyTypeToString(wrappedKeyType) + " (" + wrappedKeyType + ")");

                logKey(unwrappedKey);

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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

            encodeKey.implementation = function (input, flags) {
                const encodedString = encodeKey.call(this, input, flags);
                const lines = [];

                let flagString = base64FlagsToString(flags);

                lines.push("1. [Base64.encode(byte[] input, int flags) -> byte[]]");
                //lines.push("Input (HEX): " + bytesToHex(input, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToString(input, maxPrintableLength));
                lines.push("Input length: " + input.length);
                lines.push("Flags (Numerical): " + flags);
                lines.push("Flags (String): " + flagString);

                //lines.push("Encoded string (HEX): " + bytesToHex(encodedString, maxPrintableLength));
                lines.push("Encoded string (ASCII): " + bytesToString(encodedString, maxPrintableLength));
                lines.push("Encoded string length: " + encodedString.length);

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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

            encodeKey.implementation = function (input, offset, len, flags) {
                const encodedString = encodeKey.call(this, input, offset, len, flags);
                const lines = [];

                let flagString = base64FlagsToString(flags);

                lines.push("2. [Base64.encode(byte[input, int offset, int len, int flags]) -> byte[]]");
                //lines.push("Input (HEX): " + bytesToHexRange(input, offset, len, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToStringRange(input, offset, len, maxPrintableLength));
                lines.push("Input length: " + input.length);
                lines.push("Input offset: " + offset);
                lines.push("Input length: " + len);
                lines.push("Flags (Numerical): " + flags);
                lines.push("Flags (String): " + flagString);

                //lines.push("Encoded string (HEX): " + bytesToHex(encodedString, maxPrintableLength));
                lines.push("Encoded string (ASCII): " + bytesToString(encodedString, maxPrintableLength));
                lines.push("Encoded string length: " + encodedString.length);

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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

            encodeKey.implementation = function (input, flags) {
                const encodedString = encodeKey.call(this, input, flags);
                const lines = [];

                let flagString = base64FlagsToString(flags);

                lines.push("1. [Base64.encodeToString(byte[] input, int flags) -> java.lang.String]");
                //lines.push("Input (HEX): " + bytesToHex(input, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToString(input, maxPrintableLength));
                lines.push("Input length: " + input.length);
                lines.push("Flags (Numerical): " + flags);
                lines.push("Flags (String): " + flagString);

                lines.push("Encoded string: " + bytesToString(encodedString, maxPrintableLength));
                lines.push("Encoded string length: " + encodedString.length);

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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

            encodeKey.implementation = function (input, offset, len, flags) {
                const encodedString = encodeKey.call(this, input, offset, len, flags);
                const lines = [];

                let flagString = base64FlagsToString(flags);

                lines.push("2. [Base64.encodeToString(byte[] input, int offset, int len, int flags]) -> java.lang.String]");
                //lines.push("Input (HEX): " + bytesToHexRange(input, offset, len, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToStringRange(input, offset, len, maxPrintableLength));
                lines.push("Input length: " + input.length);
                lines.push("Input offset: " + offset);
                lines.push("Input length: " + len);
                lines.push("Flags (Numerical): " + flags);
                lines.push("Flags (String): " + flagString);

                lines.push("Encoded string: " + bytesToString(encodedString, maxPrintableLength));
                lines.push("Encoded string length: " + encodedString.length);

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                let flagString = base64FlagsToString(flags);

                lines.push("1. [Base64.decode(java.lang.String str, int flags) -> byte[]]");
                lines.push("Encoded input: " + str);
                lines.push("Flags (Numerical): " + flags);
                lines.push("Flags (String): " + flagString);

                //lines.push("Decoded output (HEX): " + bytesToHex(decodedString, maxPrintableLength));
                lines.push("Decoded output (ASCII): " + bytesToString(decodedString, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                let flagString = base64FlagsToString(flags);

                lines.push("2. [Base64.decode(byte[] input, int flags) -> byte[]]");
                //lines.push("Encoded input (HEX): " + bytesToHex(input, maxPrintableLength));
                lines.push("Encoded input (ASCII): " + bytesToString(input, maxPrintableLength));
                lines.push("Flags (Numerical): " + flags);
                lines.push("Flags (String): " + flagString);

                //lines.push("Decoded output (HEX): " + bytesToHex(decodedString, maxPrintableLength));
                lines.push("Decoded output (ASCII): " + bytesToString(decodedString, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                let flagString = base64FlagsToString(flags);

                lines.push("3. [Base64.decode(byte[] input, int offset, int len, int flags) -> byte[]]");
                //lines.push("Encoded input (HEX): " + bytesToHexRange(input, offset, len, maxPrintableLength));
                lines.push("Encoded input (ASCII): " + bytesToStringRange(input, offset, len, maxPrintableLength));
                lines.push("Flags (Numerical): " + flags);
                lines.push("Flags (String): " + flagString);

                //lines.push("Decoded output (HEX): " + bytesToHex(decodedString, maxPrintableLength));
                lines.push("Decoded output (ASCII): " + bytesToString(decodedString, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("1. [SecretKeySpec.$init(byte[] key, String algorithm) -> void]");
                lines.push("Key: " + bytesToHex(key, maxPrintableLength));
                lines.push("Algorithm: " + algorithm);
                //lines.push("getAlgorithm(): " + this.getAlgorithm());
                lines.push("getFormat(): " + this.getFormat());

                const encoded = this.getEncoded();
                lines.push("getEncoded() length: " + encoded.length);

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("2. [SecretKeySpec.$init(byte[] key, int offset, int len, String algorithm) -> void]");
                lines.push("Key: " + bytesToHex(key, maxPrintableLength));
                lines.push("Offset: " + offset);
                lines.push("Length: " + len);
                lines.push("Algorithm: " + algorithm);

                lines.push("getAlgorithm(): " + this.getAlgorithm());
                lines.push("getFormat(): " + this.getFormat());

                const encoded = this.getEncoded();
                lines.push("getEncoded() length: " + encoded.length);

                //lines.push(traceStack());

                console.log(lines.join("\n"));

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
                const lines = [];

                lines.push("1. [IvParameterSpec(byte[] iv) -> void]");
                lines.push("IV: " + bytesToHex(iv, maxPrintableLength));

                const storedIv = this.getIV();

                lines.push("Constructed IV length: " + storedIv.length);
                lines.push("Constructed IV: " + bytesToHex(storedIv, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
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
                const lines = [];

                lines.push("2. [IvParameterSpec(byte[] iv, int offset, int len) -> void]");
                lines.push("IV: " + bytesToHex(iv, maxPrintableLength));
                lines.push("Offset: " + offset);
                lines.push("Length: " + len);

                const storedIv = this.getIV();

                lines.push("Constructed IV length: " + storedIv.length);
                lines.push("Constructed IV: " + bytesToHexRange(storedIv, offset, len, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        //  -------------------------
        // | MessageDigest overloads |
        //  -------------------------
        const MessageDigest = Java.use("java.security.MessageDigest");

        //  ---------------------------------------
        // | MessageDigest.getInstance() overloads |
        //  ---------------------------------------
        try { // 1. [MessageDigest.getInstance(String algorithm) -> static MessageDigest]
            const digestKey = MessageDigest.getInstance.overload(
                "java.lang.String"
            );

            digestKey.implementation = function (algorithm) {
                const result = digestKey.call(MessageDigest, algorithm);
                const lines = [];

                lines.push("1. [MessageDigest.getInstance(String algorithm) -> static MessageDigest]");
                lines.push("Algorithm: " + algorithm);
                lines.push("Object (returned): " + result);
                lines.push("Algorithm (returned): " + result.getAlgorithm());
                lines.push("Provider: " + result.getProvider());
                lines.push("Digest length: " + result.getDigestLength());

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return result;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 2. [MessageDigest.getInstance(String algorithm, Provider provider) -> static MessageDigest]
            const digestKey = MessageDigest.getInstance.overload(
                "java.lang.String",
                "java.security.Provider"
            );

            digestKey.implementation = function (algorithm, provider) {
                const result = digestKey.call(MessageDigest, algorithm, provider);
                const lines = [];

                lines.push("2. [MessageDigest.getInstance(String algorithm, Provider provider) -> static MessageDigest]");
                lines.push("Algorithm: " + algorithm);
                lines.push("Object (returned): " + result);
                lines.push("Algorithm (returned): " + result.getAlgorithm());
                lines.push("Provider: " + provider);
                lines.push("Digest length: " + result.getDigestLength());

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return result;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 3. [MessageDigest.getInstance(String algorithm, String provider) -> static MessageDigest]
            const digestKey = MessageDigest.getInstance.overload(
                "java.lang.String",
                "java.lang.String"
            );

            digestKey.implementation = function (algorithm, provider) {
                const result = digestKey.call(MessageDigest, algorithm, provider);
                const lines = [];

                lines.push("3. [MessageDigest.getInstance(String algorithm, String provider) -> static MessageDigest]");
                lines.push("Algorithm: " + algorithm);
                lines.push("Object (returned): " + result);
                lines.push("Algorithm (returned): " + result.getAlgorithm());
                lines.push("Provider: " + provider.toString());
                lines.push("Digest length: " + result.getDigestLength());

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return result;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        //  ----------------------------------
        // | MessageDigest.digest() overloads |
        //  ----------------------------------
        try { // 1. [MessageDigest.digest() -> byte[]]
            const digestKey = MessageDigest.digest.overload();

            digestKey.implementation = function () {
                const result = digestKey.call(this);
                const lines = [];

                lines.push("1. [MessageDigest.digest() -> byte[]]");
                lines.push("Digested hash: " + bytesToHex(result, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return result;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 2. [MessageDigest.digest(byte[] input) -> byte[]]
            const digestKey = MessageDigest.digest.overload(
                "[B"
            );

            digestKey.implementation = function (input) {
                const result = digestKey.call(this, input);
                const lines = [];

                lines.push("2. [MessageDigest.digest(byte[] input) -> byte[]]");
                lines.push("Input (HEX): " + bytesToHex(input, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToString(input, maxPrintableLength));
                lines.push("Digested hash: " + bytesToHex(result, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return result;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 3. [MessageDigest.digest(byte[] buf, int offset, int len) -> int]
            const digestKey = MessageDigest.digest.overload(
                "[B",
                "int",
                "int"
            );

            digestKey.implementation = function (outputBuf, offset, len) {
                const result = digestKey.call(this, outputBuf, offset, len);
                const lines = [];

                lines.push("3. [MessageDigest.digest(byte[] buf, int offset, int len) -> int]");
                lines.push("Offset: " + offset);
                lines.push("Allocated bytes in buffer: " + len);
                lines.push("Bytes written: " + result);
                lines.push("Digested hash: " + bytesToHexRange(outputBuf, offset, result, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return result;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        //  ----------------------------------
        // | MessageDigest.update() overloads |
        //  ----------------------------------
        /*
        try { // 1. [MessageDigest.update(byte input) -> void]
            const digestKey = MessageDigest.update.overload(
                "byte"
            );

            digestKey.implementation = function (input) {
                digestKey.call(this, input);

                const lines = [];

                lines.push("1. [MessageDigest.update(byte input) -> void]");
                lines.push("Input byte: " + input);

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }
        */

        try { // 2. [MessageDigest.update(byte[] input) -> void]
            const digestKey = MessageDigest.update.overload(
                "[B"
            );

            digestKey.implementation = function (input) {
                digestKey.call(this, input);

                const lines = [];

                lines.push("2. [MessageDigest.update(byte[] input) -> void]");
                lines.push("Input bytes (HEX): " + bytesToHex(input, maxPrintableLength));
                lines.push("Input bytes (ASCII): " + bytesToString(input, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 3. [MessageDigest.update(byte[] input, int offset, int len) -> void]
            const digestKey = MessageDigest.update.overload(
                "[B",
                "int",
                "int"
            );

            digestKey.implementation = function (input, offset, len) {
                digestKey.call(this, input, offset, len);

                const lines = [];

                lines.push("3. [MessageDigest.update(byte[] input, int offset, int len) -> void]");
                lines.push("Offset (start position): " + offset);
                lines.push("Number of bytes to use from offset: " + len);
                lines.push("Input byte array (HEX): " + bytesToHexRange(input, offset, len, maxPrintableLength));
                lines.push("Input byte array (ASCII): " + bytesToStringRange(input, offset, len, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        //  ---------------
        // | Mac overloads |
        //  ---------------
        const Mac = Java.use("javax.crypto.Mac");

        //  ----------------------
        // | Mac.init() overloads |
        //  ----------------------
        try { // 1. [Mac.init(Key key) -> void]
            const macKey = Mac.init.overload(
                "java.security.Key"
            );

            macKey.implementation = function (key) {
                macKey.call(this, key);

                const lines = [];

                lines.push("1. [Mac.init(Key key) -> void]");
                lines.push("Provider: " + this.getProvider());
                lines.push("Mac length: " + this.getMacLength());

                lines.push(logKey(key));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 2. [Mac.init(Key key, AlgorithmParameterSpec params) -> void]
            const macKey = Mac.init.overload(
                "java.security.Key",
                "java.security.spec.AlgorithmParameterSpec"
            );

            macKey.implementation = function (key, params) {
                macKey.call(this, key, params);

                const lines = [];

                lines.push("2. [Mac.init(Key key, AlgorithmParameterSpec params) -> void]");
                lines.push("Algorithm: " + key.getAlgorithm());
                lines.push("Provider: " + this.getProvider());
                lines.push("Mac length: " + this.getMacLength());

                lines.push(logKey(key));
                lines.push(logAlgorithmParameterSpec(params));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        //  ------------------------
        // | Mac.update() overloads |
        //  ------------------------
        try { // 1. [Mac.update(byte input) -> void]
            const macKey = Mac.update.overload(
                "byte"
            );

            macKey.implementation = function (input) {
                macKey.call(this, input);

                const lines = [];

                lines.push("1. [Mac.update(byte input) -> void]");
                lines.push("Input byte: " + input);

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 2. [Mac.update(byte[] input) -> void]
            const macKey = Mac.update.overload(
                "[B"
            );

            macKey.implementation = function (input) {
                macKey.call(this, input);

                const lines = [];

                lines.push("2. [Mac.update(byte[] input) -> void]");
                lines.push("Input bytes (HEX): " + bytesToHex(input, maxPrintableLength));
                lines.push("Input bytes (ASCII): " + bytesToString(input, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 3. [MessageDigest.update(byte[] input, int offset, int len) -> void]
            const macKey = Mac.update.overload(
                "[B",
                "int",
                "int"
            );

            macKey.implementation = function (input, offset, len) {
                macKey.call(this, input, offset, len);

                const lines = [];

                lines.push("3. [Mac.update(byte[] input, int offset, int len) -> void]");
                lines.push("Offset (start position): " + offset);
                lines.push("Number of bytes to use from offset: " + len);
                lines.push("Input byte array (HEX): " + bytesToHexRange(input, offset, len, maxPrintableLength));
                lines.push("Input byte array (ASCII): " + bytesToStringRange(input, offset, len, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        //  -------------------------
        // | Mac.doFinal() overloads |
        //  -------------------------
        try { // 1. [Mac.doFinal() -> byte[]]
            const macKey = Mac.doFinal.overload();

            macKey.implementation = function () {
                const output = macKey.call(this);
                const lines = [];

                lines.push("1. [Mac.doFinal() -> byte[]]")

                if (output !== null) {
                    lines.push("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToString(output, maxPrintableLength));
                } else {
                    lines.push("Output: <null>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return output;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 2. [Mac.doFinal(byte[] input) -> byte[]]
            const macKey = Mac.doFinal.overload(
                "[B"
            );

            macKey.implementation = function (input) {
                const output = macKey.call(this, input);
                const lines = [];

                lines.push("2. [Mac.doFinal(byte[] input) -> byte[]]")
                lines.push("Input (HEX): " + bytesToHex(input, maxPrintableLength));
                lines.push("Input (ASCII): " + bytesToString(input, maxPrintableLength));

                if (output !== null) {
                    lines.push("Output (HEX): " + bytesToHex(output, maxPrintableLength));
                    lines.push("Output (ASCII): " + bytesToString(output, maxPrintableLength));
                } else {
                    lines.push("Output: <null>");
                }

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return output;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }

        try { // 3. [Mac.doFinal(byte[] output, int outOffset) -> void]
            const macKey = Mac.doFinal.overload(
                "[B",
                "int"
            );

            macKey.implementation = function (output, outputOffset) {
                macKey.call(this, output, outputOffset);

                const lines = [];

                lines.push("3. [Mac.doFinal(byte[] output, int outputOffset) -> void]");

                lines.push("Bytes written: " + output.length);
                lines.push("Output (HEX): " + bytesToHexRange(output, outputOffset, output.length, maxPrintableLength));
                lines.push("Output (ASCII): " + bytesToStringRange(output, outputOffset, output.length, maxPrintableLength));

                //lines.push(traceStack());

                console.log(lines.join("\n"));

                return outputLen;
            };
        } catch (e) {
            console.log("[+] Error message: " + e.message);
        }
    });
}, 0);