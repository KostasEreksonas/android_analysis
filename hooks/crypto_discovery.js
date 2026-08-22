'use strict';

const maxPrintableLength = 48; // Limit length of logged hex and ascii strings
const Log = Java.use("android.util.Log");
const Throwable = Java.use("java.lang.Throwable");

function traceStack() {
    return Log.getStackTraceString(Throwable.$new());
}

function logging(state) {
    console.log(state.objectId + ":" + JSON.stringify(state, null, 2));
}

function fingerprint(bytes) {
    // Compute a 32-bit FNV-1a hash
    if (bytes === null || bytes === undefined) return "<null>";

    let h = 2166136261;
    for (let i = 0; i < bytes.length; i++) {
        h ^= (bytes[i] & 0xFF);
        h = Math.imul(h, 16777619);
    }

    return (h >>> 0).toString(16).padStart(8, "0") + ":" + bytes.length;
}

function bytesToHex(bytes, maxLength) {
    if (bytes === null || bytes === undefined) return "<null>";

    let result = "";

    // If maxLength === 0, parse whole byte array
    // Truncate the log entry if maxLength < bytes.length
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
    if (bytes === null || bytes === undefined) return "<null>";

    let result = "";

    // If maxLength === 0, parse whole byte array
    // Truncate the log entry if maxLength < bytes.length
    const hasLimit = typeof maxLength === "number" && maxLength > 0;
    const len = hasLimit ? Math.min(maxLength, length) : length;

    for (let i = offset; i < (offset + len); i++) {
        let v = bytes[i];

        if (v < 0)
            v += 256;

        result += ("0" + v.toString(16)).slice(-2);
    }

    if (hasLimit && length > len) {
        result += ` ... [${length - len} more bytes]`;
    }

    return result;
}

function bytesToString(bytes, maxLength) {
    if (bytes === null || bytes === undefined) return "<null>";

    let result = '';

    // If maxLength === 0, parse whole byte array
    // Truncate the log entry if maxLength < bytes.length
    const hasLimit = typeof maxLength === "number" && maxLength > 0;
    const len = hasLimit ? Math.min(maxLength, bytes.length) : bytes.length;

    for (let i = 0; i < len; ++i) {
        // Only convert printable ASCII characters (32-126); otherwise, use a placeholder dot (.)
        let val = bytes[i] & 0xFF;  // Get unsigned byte value

        if (val === 10) {
            result += "\\n";
        } else if (val === 13) {
            result += "\\r";
        } else if (val === 9) {
            result += "\\t";
        } else if (val >= 32 && val <= 126) {
            result += String.fromCharCode(val);
        } else {
            result += '.';
        }
    }

    if (hasLimit && bytes.length > len) {
        result += ` ... [${bytes.length - len} more bytes]`;
    }

    return result;
}

function bytesToStringRange(bytes, offset, length, maxLength) {
    if (bytes === null || bytes === undefined) return "<null>";

    let result = '';

    // If maxLength === 0, parse whole byte array
    // Truncate the log entry if maxLength < bytes.length
    const hasLimit = typeof maxLength === "number" && maxLength > 0;
    const len = hasLimit ? Math.min(maxLength, length) : length;

    for (let i = offset; i < (offset + len); ++i) {
        // Only convert printable ASCII characters (32-126); otherwise, use a placeholder dot (.)
        let val = bytes[i] & 0xFF;  // Get unsigned byte value

        if (val === 10) {
            result += "\\n";
        } else if (val === 13) {
            result += "\\r";
        } else if (val === 9) {
            result += "\\t";
        } else if (val >= 32 && val <= 126) {
            result += String.fromCharCode(val);
        } else {
            result += '.';
        }
    }

    if (hasLimit && length > len) {
        result += ` ... [${length - len} more bytes]`;
    }

    return result;
}

function logKey(state, key, name) {
    if (key === null) return;

    state.keyClass = key.$className;
    state.keyAlgorithm = key.getAlgorithm();
    state.keyFormat = key.getFormat();

    const encoded = key.getEncoded();

    if (encoded !== null) {
        if (name === "Cipher") {
            state.keyBytesHex = bytesToHex(encoded, maxPrintableLength);
        } else if (name === "Mac") {
            state.keyBytesString = bytesToString(encoded, maxPrintableLength);
        }

        state.keyBytesFingerprint = fingerprint(encoded);
    } else {
        state.keyBytes = "<unavailable>";
    }
}

function logAlgorithmParameters(state, params) {
    if (params === null) return;

    state.parameterClass = params.$className;
    state.parameterAlgorithm = params.getAlgorithm();

    const encoded = params.getEncoded();

    if (encoded !== null) {
        state.parameterEncoded = bytesToHex(params.getEncoded(), maxPrintableLength);
    } else {
        state.parameterEncoded = "<undefined>";
    }
}

function logAlgorithmParameterSpec(state, params) {
    if (params === null)
        return;

    state.parameterClass = params.$className;

    if (params.$className === "javax.crypto.spec.IvParameterSpec") {
        const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        const ivSpec = Java.cast(params, IvParameterSpec);
        state.iv = bytesToHex(ivSpec.getIV(), maxPrintableLength);
        state.ivFingerprint = fingerprint(ivSpec.getIV());
    }

    if (params.$className === "javax.crypto.spec.GCMParameterSpec") {
        const GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
        const gcm = Java.cast(params, GCMParameterSpec);
        state.gcmIv = bytesToHex(gcm.getIV(), maxPrintableLength);
        state.gcmTagBits = gcm.getTLen();
    }
}

function describeOpmode(opmode) {
    if (opmode === 1) {
        return "ENCRYPT";
    } else if (opmode === 2) {
        return "DECRYPT";
    } else if (opmode === 3) {
        return "WRAP";
    } else if (opmode === 4) {
        return "UNWRAP";
    }
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

function getObjectId(name, obj) {
    if (obj === null || obj === undefined) return name + "-<null>";

    return name + "-" + obj.hashCode().toString();
};

Java.perform(function () {
    const cipherStates = new Map();
    const macStates = new Map();

    let decodeBase64Counter = 0;
    let encodeBase64Counter = 0;
    let encodeToStringBase64Counter = 0;

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
            const provider = cipher.getProvider();
            const objectId = getObjectId("Cipher", cipher);

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                instanceOverload: "1. [Cipher.getInstance(java.lang.String) -> static Cipher]",
                transformation: transformation,
                algorithm: cipher.getAlgorithm(),
                runtimeClass: cipher.getClass().getName(),
                providerName: provider.getName(),
                providerVersion: provider.getVersion(),
                providerInfo: provider.getInfo(),
                providerClass: provider.getClass().getName(),
                updateInputs: [],
                updateInputsLen: [],
                updateOutputs: [],
                updateOutputsLen: []
            };

            cipherStates.set(objectId, state);

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
            const cipherProvider = cipher.getProvider();
            const objectId = getObjectId("Cipher", cipher);

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                instanceOverload: "2. [Cipher.getInstance(java.lang.String, java.lang.String) -> static Cipher]",
                transformation: transformation,
                algorithm: cipher.getAlgorithm(),
                runtimeClass: cipher.getClass().getName(),
                providerName: cipherProvider.getName(),
                providerVersion: cipherProvider.getVersion(),
                providerInfo: cipherProvider.getInfo(),
                providerClass: cipherProvider.getClass().getName(),
                updateInputs: [],
                updateInputsLen: [],
                updateOutputs: [],
                updateOutputsLen: []
            };

            cipherStates.set(objectId, state);

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
            const objectId = getObjectId("Cipher", cipher);

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                instanceOverload: "3. [Cipher.getInstance(java.lang.String, java.security.Provider) -> static Cipher]",
                transformation: transformation,
                algorithm: cipher.getAlgorithm(),
                runtimeClass: cipher.getClass().getName(),
                providerName: provider.getName(),
                providerVersion: provider.getVersion(),
                providerInfo: provider.getInfo(),
                providerClass: provider.getClass().getName(),
                updateInputs: [],
                updateInputsLen: [],
                updateOutputs: [],
                updateOutputsLen: []
            };

            cipherStates.set(objectId, state);

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
            const objectId = getObjectId("Cipher", this);

            initKey.call(this, opmode, certificate);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.initOverload = "1. [Cipher.init(int opmode, Certificate certificate) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);
                state.certificateType = certificate.getType();
                state.publicKey = bytesToHex(certificate.getPublicKey().getEncoded(), maxPrintableLength);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }
            };
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
            const objectId = getObjectId("Cipher", this);

            initKey.call(this, opmode, certificate, random);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.initOverload = "2. [Cipher.init(int opmode, Certificate certificate, SecureRandom random) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);
                state.certificateType = certificate.getType();
                state.publicKey = bytesToHex(certificate.getPublicKey().getEncoded(), maxPrintableLength);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }
            };
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
            const objectId = getObjectId("Cipher", this);

            initKey.call(this, opmode, key);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.initOverload = "3. [Cipher.init(int opmode, Key key) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key, "Cipher");
            };
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
            const objectId = getObjectId("Cipher", this);

            initKey.call(this, opmode, key, params);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.initOverload = "4. [Cipher.init(int opmode, Key key, AlgorithmParameters params) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key, "Cipher");
                logAlgorithmParameters(state, params);
            };
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
            const objectId = getObjectId("Cipher", this);

            initKey.call(this, opmode, key, params);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.initOverload = "5. [Cipher.init(int opmode, Key key, AlgorithmParameterSpec params) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key, "Cipher");
                logAlgorithmParameterSpec(state, params);
            };
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
            const objectId = getObjectId("Cipher", this);

            initKey.call(this, opmode, key, params, random);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.initOverload = "6. [Cipher.init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key, "Cipher");
                logAlgorithmParameterSpec(state, params);

                state.secureRandom = random !== null ? String(random.getClass().getName()) : "<null>";
            };
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
            const objectId = getObjectId("Cipher", this);

            initKey.call(this, opmode, key, params, random);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.initOverload = "7. [Cipher.init(int opmode, Key key, AlgorithmParameters params, SecureRandom random) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key, "Cipher");
                logAlgorithmParameters(state, params);

                state.secureRandom = random !== null ? String(random.getClass().getName()) : "<null>";
            };
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
            const objectId = getObjectId("Cipher", this);

            initKey.call(this, opmode, key, random);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.initOverload = "8. [Cipher.init(int opmode, Key key, SecureRandom random) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key, "Cipher");

                state.secureRandom = random !== null ? String(random.getClass().getName()) : "<null>";
            };
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
            const objectId = getObjectId("Cipher", this);
            const output = updateKey.call(this, input);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.updateOverload = "1. [Cipher.update(byte[] input) -> byte[]]";
                state.updateInputs.push(bytesToHex(input, maxPrintableLength));
                state.updateInputsLen.push(input.length);
                state.updateOutputs.push(bytesToHex(output, maxPrintableLength));
                state.updateOutputsLen.push(output.length);
            }

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
            const objectId = getObjectId("Cipher", this);
            const output = updateKey.call(this, input, inputOffset, inputLen);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.updateOverload = "2. [Cipher.update(byte[] input, int inputOffset, int inputLen) -> byte[]]";
                state.updateInputs.push(bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
                state.updateInputsLen.push(inputLen);

                if (output !== null) {
                    state.updateOutputs.push(bytesToHex(output, maxPrintableLength));
                    state.updateOutputsLen.push(output.length);
                } else {
                    state.updateOutputs.push("");
                    state.updateOutputsLen.push(0);
                }
            }

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
            const objectId = getObjectId("Cipher", this);
            const outputLen = updateKey.call(this, input, inputOffset, inputLen, output);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.updateOverload = "3. [Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]";
                state.updateInputs.push(bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
                state.updateInputsLen.push(inputLen);

                if (outputLen > 0) {
                    state.updateOutputs.push(bytesToHexRange(output, 0, outputLen, maxPrintableLength));
                    state.updateOutputsLen.push(outputLen);
                } else {
                    state.updateOutputs.push("");
                    state.updateOutputsLen.push(0);
                }
            }

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
            const objectId = getObjectId("Cipher", this);
            const outputLen = updateKey.call(this, input, inputOffset, inputLen, output, outputOffset);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.updateOverload = "4. [Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]";
                state.updateInputs.push(bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength));
                state.updateInputsLen.push(inputLen);

                if (outputLen > 0) {
                    state.updateOutputs.push(bytesToHexRange(output, outputOffset, outputLen, maxPrintableLength));
                    state.updateOutputsLen.push(outputLen);
                } else {
                    state.updateOutputs.push("");
                    state.updateOutputsLen.push(0);
                }
            }

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
            const objectId = getObjectId("Cipher", this);
            const output = finalKey.call(this);

            let state = cipherStates.get(objectId);

            if (output !== null && state !== undefined) {
                state.finalOverload = "1. [Cipher.doFinal() -> byte[]]";
                state.bytesWritten = output.length;

                if (state.opmode === 1) {
                    state.output = bytesToHex(output, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.output = bytesToString(output, maxPrintableLength);
                }
            
                state.outputFingerprint = fingerprint(output);
                state.stackTrace = traceStack();
            }

            if (state) logging(state);

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
            const objectId = getObjectId("Cipher", this);
            const output = finalKey.call(this, input);

            let state = cipherStates.get(objectId);

            if (output !== null && state !== undefined) {
                state.finalOverload = "2. [Cipher.doFinal(byte[] input) -> byte[]]";
                state.bytesWritten = output.length;

                if (state.opmode === 1) {
                    state.input = bytesToString(input, maxPrintableLength);
                    state.output = bytesToHex(output, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.input = bytesToHex(input, maxPrintableLength);
                    state.output = bytesToString(output, maxPrintableLength);
                }
            
                state.outputFingerprint = fingerprint(output);
                state.stackTrace = traceStack();
            }

            if (state) logging(state);

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
            const objectId = getObjectId("Cipher", this);
            const outputLen = finalKey.call(this, output, outputOffset);

            let state = cipherStates.get(objectId);

            if (outputLen > 0 && state !== undefined) {
                state.finalOverload = "3. [Cipher.doFinal(byte[] output int outputOffset) -> int]";

                state.bytesWritten = output.length;

                if (state.opmode === 1) {
                    state.output = bytesToHexRange(output, outputOffset, outputLen, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.output = bytesToStringRange(output, outputOffset, outputLen, maxPrintableLength);
                }
            
                state.outputFingerprint = fingerprint(output);
                state.stackTrace = traceStack();
            }

            if (state) logging(state);

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
            const objectId = getObjectId("Cipher", this);
            const output = finalKey.call(this, input, inputOffset, inputLen);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.finalOverload = "4. [Cipher.doFinal(byte[] input int inputOffset, int inputLen) -> byte[]]";

                state.bytesWritten = output.length;

                if (state.opmode === 1) {
                    state.input = bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToHex(output, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.input = bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToString(output, maxPrintableLength);
                }
            
                state.outputFingerprint = fingerprint(output);
                state.stackTrace = traceStack();
            }

            if (state) logging(state);

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
            const objectId = getObjectId("Cipher", this);
            const outputLen = finalKey.call(this, input, inputOffset, inputLen, output);

            let state = cipherStates.get(objectId);

            if (outputLen > 0 && state !== undefined) {
                state.finalOverload = "5. [Cipher.doFinal(byte[] input int inputOffset, int inputLen, byte[] output) -> int]";

                state.bytesWritten = outputLen;

                if (state.opmode === 1) {
                    state.input = bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToHexRange(output, 0, outputLen, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.input = bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToStringRange(output, 0, outputLen, maxPrintableLength);
                }
            
                state.outputFingerprint = fingerprint(output);
                state.stackTrace = traceStack();
            }

            if (state) logging(state);

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
            const objectId = getObjectId("Cipher", this);
            const outputLen = finalKey.call(this, input, inputOffset, inputLen, output, outputOffset);

            let state = cipherStates.get(objectId);

            if (outputLen > 0 && state !== undefined) {
                state.finalOverload = "6. [Cipher.doFinal(byte[] input int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]";

                state.bytesWritten = outputLen;

                if (state.opmode === 1) {
                    state.input = bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToHexRange(output, outputOffset, outputLen, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.input = bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToStringRange(output, outputOffset, outputLen, maxPrintableLength);
                }
            
                state.outputFingerprint = fingerprint(output);
                state.stackTrace = traceStack();
            }

            if (state) logging(state);

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
            const objectId = getObjectId("Cipher", this);
            const outputLen = finalKey.call(this, input, output);
            const duplicateInput = input.duplicate();
            const duplicateOutput = output.duplicate();

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.finalOverload = "7. [Cipher.doFinal(ByteBuffer input, ByteBuffer output) -> int]";
                state.bytesWritten = outputLen;

                if (state.opmode === 1) {
                    state.input = bytesToString(duplicateInput, maxPrintableLength);
                    state.output = bytesToHex(duplicateOutput, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.input = bytesToHex(duplicateInput, maxPrintableLength);
                    state.output = bytesToString(duplicateOutput, maxPrintableLength);
                }
            
                state.outputFingerprint = fingerprint(output);
                state.stackTrace = traceStack();
            }

            if (state) logging(state);

            return outputLen;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  ---------------
    // | Mac overloads |
    //  ---------------
    const Mac = Java.use("javax.crypto.Mac");

    //  -----------------------------
    // | Mac.getInstance() overloads |
    //  -----------------------------
    try {// 1. [Mac.getInstance(java.lang.String) -> static Mac]
        const instanceKey = Mac.getInstance.overload(
            "java.lang.String"
        );

        instanceKey.implementation = function (transformation) {
            const instance = instanceKey.call(Mac, transformation);
            const provider = instance.getProvider();
            const objectId = getObjectId("Mac", instance);

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                instanceOverload: "1. [Mac.getInstance(java.lang.String) -> static Mac]",
                transformation: transformation,
                algorithm: instance.getAlgorithm(),
                runtimeClass: instance.getClass().getName(),
                providerName: provider.getName(),
                providerVersion: provider.getVersion(),
                providerInfo: provider.getInfo(),
                providerClass: provider.getClass().getName(),
                updateCount: 0,
                updates: []
            };

            macStates.set(objectId, state);

            return instance;
        }
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Mac.getInstance(java.lang.String, java.lang.String) -> static Mac]
        const instanceKey = Mac.getInstance.overload(
            "java.lang.String",
            "java.lang.String"
        );

        instanceKey.implementation = function (transformation, provider) {
            const instance = instanceKey.call(Mac, transformation, provider);
            const macProvider = instance.getProvider();
            const objectId = getObjectId("Mac", instance);

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                instanceOverload: "2. [Mac.getInstance(java.lang.String, java.lang.String) -> static Mac]",
                transformation: transformation,
                algorithm: instance.getAlgorithm(),
                runtimeClass: instance.getClass().getName(),
                providerName: macProvider.getName(),
                providerVersion: macProvider.getVersion(),
                providerInfo: macProvider.getInfo(),
                providerClass: macProvider.getClass().getName(),
                updateCount: 0,
                updates: []
            };

            macStates.set(objectId, state);

            return instance;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 3. [Mac.getInstance(java.lang.String, java.security.Provider) -> static Mac]
        const instanceKey = Mac.getInstance.overload(
            "java.lang.String",
            "java.security.Provider"
        );

        instanceKey.implementation = function (transformation, provider) {
            const instance = instanceKey.call(Mac, transformation, provider);
            const objectId = getObjectId("Mac", instance);

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                instanceOverload: "3. [Mac.getInstance(java.lang.String, java.security.Provider) -> static Mac]",
                transformation: transformation,
                algorithm: instance.getAlgorithm(),
                runtimeClass: instance.getClass().getName(),
                providerName: provider.getName(),
                providerVersion: provider.getVersion(),
                providerInfo: provider.getInfo(),
                providerClass: provider.getClass().getName(),
                updateCount: 0,
                updates: []
            };

            macStates.set(objectId, state);

            return instance;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  ----------------------
    // | Mac.init() overloads |
    //  ----------------------
    try { // 1. [Mac.init(Key key) -> void]
        const macKey = Mac.init.overload(
            "java.security.Key"
        );

        macKey.implementation = function (key) {
            macKey.call(this, key);

            const objectId = getObjectId("Mac", this);

            let state = macStates.get(objectId);

            if (state !== undefined) {
                state.initOverload = "1. [Mac.init(Key key) -> void]";
                state.macLength = this.getMacLength();

                logKey(state, key, "Mac");
            };

            if (state) logging(state);

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

            const objectId = getObjectId("Mac", this);

            let state = macStates.get(objectId);

            if (state !== undefined) {
                state.initOverload = "2. [Mac.init(Key key, AlgorithmParameterSpec params) -> void]";

                logKey(state, key, "Mac");
                console.log("Params: " + params);
                logAlgorithmParameterSpec(state, params);
            };

            if (state) logging(state);
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 1. [Mac.update(byte[] input) -> void]
        const macKey = Mac.update.overload(
            "[B"
        );

        macKey.implementation = function (input) {
            macKey.call(this, input);

            const objectId = getObjectId("Mac", this);

            let state = macStates.get(objectId);

            if (state !== undefined) {
                state.updateOverload = "1. [Mac.update(byte[] input) -> void]";
                state.updateCount++;
                state.updates.push(bytesToHex(input, maxPrintableLength));
            };
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    try { // 2. [Mac.update(byte[] input, int offset, int len) -> void]
        const macKey = Mac.update.overload(
            "[B",
            "int",
            "int"
        );

        macKey.implementation = function (input, offset, len) {
            macKey.call(this, input, offset, len);

            const objectId = getObjectId("Mac", this);

            let state = macStates.get(objectId);

            if (state !== undefined) {
                state.updateOverload = "2. [Mac.update(byte[] input, int offset, int len) -> void]";
                state.updateCount++;
                state.updates.push(bytesToHexRange(input, offset, len, maxPrintableLength));
            };
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
            const objectId = getObjectId("Mac", this);

            let state = macStates.get(objectId);

            if (state !== undefined) {
                state.finalOverload = "1. [Mac.doFinal() -> byte[]]";

                const macLength = this.getMacLength();
                state.bytesWritten = macLength;

                if (output !== null) {
                    state.output = bytesToHex(output, maxPrintableLength);
                    state.outputFingerprint = fingerprint(output);
                } else {
                    state.output = "<undefined>";
                }
            };

            state.stackTrace = traceStack();
            if (state) logging(state);

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
            const objectId = getObjectId("Mac", this);

            let state = macStates.get(objectId);

            if (state !== undefined) {
                state.finalOverload = "2. [Mac.doFinal(byte[] input) -> byte[]]";
                state.inputHex = bytesToHex(input, maxPrintableLength);
                state.inputString = bytesToString(input, maxPrintableLength);
                state.inputFingerprint = fingerprint(input);

                const macLength = this.getMacLength();
                state.bytesWritten = macLength;

                state.updates.push(bytesToString(input, maxPrintableLength));
                state.updateCount++;

                if (output !== null) {
                    state.output = bytesToHex(output, maxPrintableLength);
                    state.outputFingerprint = fingerprint(output);
                } else {
                    state.output = "<undefined>";
                }
            };

            state.stackTrace = traceStack();
            if (state) logging(state);

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
            const objectId = getObjectId("Mac", this);

            let state = macStates.get(objectId);

            if (state !== undefined) {
                state.finalOverload = "3. [Mac.doFinal(byte[] output, int outOffset) -> byte[]]";

                const macLength = this.getMacLength();
                state.bytesWritten = macLength;

                if (output !== null) {
                    state.output = bytesToHexRange(output, outputOffset, macLength, maxPrintableLength);
                } else {
                    state.output = "<undefined>";
                }
            };

            state.stackTrace = traceStack();
            if (state) logging(state);
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
            const objectId = "encodeBase64-" + encodeBase64Counter;
            const flagString = base64FlagsToString(flags);
            encodeBase64Counter++;

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                overload: "1. [Base64.encode(byte[] input, int flags) -> byte[]]",
                inputHex: bytesToHex(input, maxPrintableLength),
                inputString: bytesToString(input, maxPrintableLength),
                inputLength: input.length,
                flagNumerical: flags,
                flagString: flagString,
                //outputHex: bytesToHex(encodedString, maxPrintableLength),
                outputString: bytesToString(encodedString, maxPrintableLength),
                outputLength: encodedString.length,
                inputFingerprint: fingerprint(input),
                outputFingerprint: fingerprint(encodedString),
                stackTrace: traceStack()
            }

            if (state) logging(state);

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
            const objectId = "encodeBase64-" + encodeBase64Counter;
            const flagString = base64FlagsToString(flags);
            encodeBase64Counter++;

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                overload: "2. [Base64.encode(byte[] input, int offset, int len, int flags]) -> byte[]]",
                inputHex: bytesToHexRange(input, offset, len, maxPrintableLength),
                inputString: bytesToStringRange(input, offset, len, maxPrintableLength),
                inputLength: input.length,
                inputOffset: offset,
                inputLen: len,
                flagNumerical: flags,
                flagString: flagString,
                outputHex: bytesToHex(encodedString, maxPrintableLength),
                outputString: bytesToString(encodedString, maxPrintableLength),
                outputLength: encodedString.length,
                inputFingerprint: fingerprint(input),
                outputFingerprint: fingerprint(encodedString),
                stackTrace: traceStack()
            }

            if (state) logging(state);

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
            const objectId = "encodeToStringBase64-" + encodeToStringBase64Counter;
            const flagString = base64FlagsToString(flags);
            encodeToStringBase64Counter++;

            let truncated = "";
            if (encodedString.length > maxPrintableLength) {
                truncated = encodedString.substring(0, maxPrintableLength);
                truncated += ` ... [${encodedString.length - maxPrintableLength} more bytes]`;
            } else {
                truncated = encodedString;
            }

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                overload: "1. [Base64.encodeToString(byte[] input, int flags) -> java.lang.String]",
                inputHex: bytesToHex(input, maxPrintableLength),
                inputString: bytesToString(input, maxPrintableLength),
                inputLength: input.length,
                flagNumerical: flags,
                flagString: flagString,
                outputString: truncated,
                outputLength: encodedString.length,
                inputFingerprint: fingerprint(input),
                outputFingerprint: fingerprint(encodedString),
                stackTrace: traceStack()
            }

            if (state) logging(state);

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
            const objectId = "encodeToStringBase64-" + encodeToStringBase64Counter;
            const flagString = base64FlagsToString(flags);
            encodeToStringBase64Counter++;

            let truncated = "";
            if (encodedString.length > maxPrintableLength) {
                truncated = encodedString.substring(0, maxPrintableLength);
                truncated += ` ... [${encodedString.length - maxPrintableLength} more bytes]`;
            } else {
                truncated = encodedString;
            }

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                overload: "2. [Base64.encodeToString(byte[input, int offset, int len, int flags]) -> java.lang.String]",
                inputHex: bytesToHexRange(input, offset, len, maxPrintableLength),
                inputString: bytesToStringRange(input, offset, len, maxPrintableLength),
                inputLength: input.length,
                inputOffset: offset,
                inputLen: len,
                flagNumerical: flags,
                flagString: flagString,
                outputString: truncated,
                outputLength: encodedString.length,
                inputFingerprint: fingerprint(input),
                outputFingerprint: fingerprint(encodedString),
                stackTrace: traceStack()
            }

            if (state) logging(state);

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
            const objectId = "decodeBase64-" + decodeBase64Counter;
            const flagString = base64FlagsToString(flags);
            decodeBase64Counter++;

            let truncated = "";
            if (str.length > maxPrintableLength) {
                truncated = str.substring(0, maxPrintableLength);
                truncated += ` ... [${str.length - maxPrintableLength} more bytes]`;
            } else {
                truncated = str;
            }

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                overload: "1. [Base64.decode(java.lang.String str, int flags) -> byte[]]",
                encodedInput: truncated,
                inputLength: str.length,
                flagNumerical: flags,
                flagString: flagString,
                outputHex: bytesToHex(decodedString, maxPrintableLength),
                outputString: bytesToString(decodedString, maxPrintableLength),
                outputLength: decodedString.length,
                inputFingerprint: fingerprint(str),
                outputFingerprint: fingerprint(decodedString),
                stackTrace: traceStack()
            }

            if (state) logging(state);

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
            const objectId = "decodeBase64-" + decodeBase64Counter;
            const flagString = base64FlagsToString(flags);
            decodeBase64Counter++;

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                overload: "2. [Base64.decode(byte[] input, int flags) -> byte[]]",
                encodedInputHex: bytesToHex(input, maxPrintableLength),
                encodedInputString: bytesToString(input, maxPrintableLength),
                inputLength: input.length,
                flagNumerical: flags,
                flagString: flagString,
                outputHex: bytesToHex(decodedString, maxPrintableLength),
                outputString: bytesToString(decodedString, maxPrintableLength),
                outputLength: decodedString.length,
                inputFingerprint: fingerprint(input),
                outputFingerprint: fingerprint(decodedString),
                stackTrace: traceStack()
            }

            if (state) logging(state);

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
            const objectId = "decodeBase64-" + decodeBase64Counter;
            const flagString = base64FlagsToString(flags);
            decodeBase64Counter++;

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                overload: "3. [Base64.decode(byte[] input, int offset, int len, int flags) -> byte[]]",
                encodedInputHex: bytesToHexRange(input, offset, len, maxPrintableLength),
                encodedInputString: bytesToStringRange(input, offset, len, maxPrintableLength),
                inputLength: input.length,
                flagNumerical: flags,
                flagString: flagString,
                outputHex: bytesToHex(decodedString, maxPrintableLength),
                outputString: bytesToString(decodedString, maxPrintableLength),
                outputLength: decodedString.length,
                inputFingerprint: fingerprint(input),
                outputFingerprint: fingerprint(decodedString),
                stackTrace: traceStack()
            }

            if (state) logging(state);

            return decodedString;
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }
});