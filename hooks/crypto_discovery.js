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
    if (bytes === null || bytes === undefined) {
        return "<null>";
    }

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

    if (hasLimit && length > len) {
        result += ` ... [${length - len} more bytes]`;
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
    if (bytes === null || bytes === undefined) {
        return "<null>";
    }

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

    if (hasLimit && length > len) {
        result += ` ... [${length - len} more bytes]`;
    }

    return result;
}

function logKey(state, key) {
    if (key === null)
        return;

    state.keyClass = key.$className;
    state.keyAlgorithm = key.getAlgorithm();
    state.keyFormat = key.getFormat();

    const encoded = key.getEncoded();

    if (encoded !== null) {
        state.keyBytes = bytesToHex(encoded, maxPrintableLength);
    } else {
        state.keyBytes = "<unavailable>";
    }
}

function logAlgorithmParameters(state, params) {
    if (params === null)
        return;

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

function getObjectId(name, obj) {
    if (obj === null || obj === undefined) {
        return name + "-<null>";
    }

    return name + "-" + obj.hashCode().toString();
};

function logging(state) {
    const keys = Object.keys(state);
    let final = "";
    for (const key of keys) {
        try {
            final += key + ": " + state[key] + "\n";
        } catch (e) {
            console.log(
                "[!] FAILED FIELD: " + key +
                " | type: " + typeof state[key] +
                " | error: " + e
            );
        }
    }

    console.log(final);
}

Java.perform(function () {
    const cipherStates = new Map();
    const macStates = new Map();

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
                instanceOverload: "[Cipher.getInstance(java.lang.String) -> static Cipher]",
                transformation: transformation,
                algorithm: cipher.getAlgorithm(),
                runtimeClass: cipher.getClass().getName(),
                providerName: provider.getName(),
                providerVersion: provider.getVersion(),
                providerInfo: provider.getInfo(),
                providerClass: provider.getClass().getName(),
                updateCount: 0
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
                instanceOverload: "[Cipher.getInstance(java.lang.String, java.lang.String) -> static Cipher]",
                transformation: transformation,
                algorithm: cipher.getAlgorithm(),
                runtimeClass: cipher.getClass().getName(),
                providerName: cipherProvider.getName(),
                providerVersion: cipherProvider.getVersion(),
                providerInfo: cipherProvider.getInfo(),
                providerClass: cipherProvider.getClass().getName(),
                updateCount: 0
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
                instanceOverload: "[Cipher.getInstance(java.lang.String, java.security.Provider) -> static Cipher]",
                transformation: transformation,
                algorithm: cipher.getAlgorithm(),
                runtimeClass: cipher.getClass().getName(),
                providerName: provider.getName(),
                providerVersion: provider.getVersion(),
                providerInfo: provider.getInfo(),
                providerClass: provider.getClass().getName(),
                updateCount: 0
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
                state.initOverload = "[Cipher.init(int opmode, Certificate certificate) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);
                state.certificateType = certificate.getType();
                state.publicKey = certificate.getPublicKey();

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
                state.initOverload = "[Cipher.init(int opmode, Certificate certificate, SecureRandom random) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);
                state.certificateType = certificate.getType();
                state.publicKey = certificate.getPublicKey();

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
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key);
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
                state.initOverload = "[Cipher.init(int opmode, Key key, AlgorithmParameters params) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key);
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
                state.initOverload = "[Cipher.init(int opmode, Key key, AlgorithmParameterSpec params) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key);
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
                state.initOverload = "[Cipher.init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key);
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
                state.initOverload = "[Cipher.init(int opmode, Key key, AlgorithmParameters params, SecureRandom random) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key);
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
                state.initOverload = "[Cipher.init(int opmode, Key key, SecureRandom random) -> void]";
                state.opmode = opmode;
                state.opmodeString = describeOpmode(opmode);

                try {
                    state.blockSize = this.getBlockSize();
                } catch (e) {
                    state.blockSize = "<unavailable>";
                }

                logKey(state, key);

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
                state.updateOverload = "[Cipher.update(byte[] input) -> byte[]]";
                state.updateCount++;
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
                state.updateOverload = "[Cipher.update(byte[] input, int inputOffset, int inputLen) -> byte[]]";
                state.updateCount++;
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
                state.updateOverload = "[Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output) -> int]";
                state.updateCount++;
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
                state.updateOverload = "[Cipher.update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]";
                state.updateCount++;
            }

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
            const objectId = getObjectId("Cipher", this);
            const outputLen = updateKey.call(this, input, output);

            let state = cipherStates.get(objectId);

            if (state !== undefined) {
                state.updateOverload = "[Cipher.update(ByteBuffer input, ByteBuffer output) -> byte[]]";
                state.updateCount++;
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
                state.finalOverload = "[Cipher.doFinal() -> byte[]]";
                state.bytesWritten = output.length;

                if (state.opmode === 1) {
                    state.output = bytesToHex(output, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.output = bytesToString(output, maxPrintableLength);
                }
            }

            logging(state);

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
                state.finalOverload = "[Cipher.doFinal(byte[] input) -> byte[]]";
                state.bytesWritten = output.length;

                if (state.opmode === 1) {
                    state.input = bytesToString(input, maxPrintableLength);
                    state.output = bytesToHex(output, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.input = bytesToHex(input, maxPrintableLength);
                    state.output = bytesToString(output, maxPrintableLength);
                }
            }

            logging(state);

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
                state.finalOverload = "[Cipher.doFinal(byte[] output int outputOffset) -> int]";

                state.bytesWritten = output.length;

                if (state.opmode === 1) {
                    state.output = bytesToHexRange(output, outputOffset, outputLen, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.output = bytesToStringRange(output, outputOffset, outputLen, maxPrintableLength);
                }
            }

            logging(state);

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
                state.finalOverload = "[Cipher.doFinal(byte[] input int inputOffset, int inputLen) -> byte[]]";

                state.bytesWritten = output.length;

                if (state.opmode === 1) {
                    state.input = bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToHex(output, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.input = bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToString(output, maxPrintableLength);
                }
            }

            logging(state);

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
                state.finalOverload = "[Cipher.doFinal(byte[] input int inputOffset, int inputLen, byte[] output) -> int]";

                state.bytesWritten = outputLen;

                if (state.opmode === 1) {
                    state.input = bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToHexRange(output, 0, outputLen, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.input = bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToStringRange(output, 0, outputLen, maxPrintableLength);
                }
            }

            logging(state);

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
                state.finalOverload = "[Cipher.doFinal(byte[] input int inputOffset, int inputLen, byte[] output, int outputOffset) -> int]";

                state.bytesWritten = outputLen;

                if (state.opmode === 1) {
                    state.input = bytesToStringRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToHexRange(output, outputOffset, outputLen, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.input = bytesToHexRange(input, inputOffset, inputLen, maxPrintableLength);
                    state.output = bytesToStringRange(output, outputOffset, outputLen, maxPrintableLength);
                }
            }

            logging(state);

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
                state.finalOverload = "[Cipher.doFinal(ByteBuffer input, ByteBuffer output) -> int]";
                state.bytesWritten = outputLen;

                if (state.opmode === 1) {
                    state.input = bytesToString(duplicateInput, maxPrintableLength);
                    state.output = bytesToHex(duplicateOutput, maxPrintableLength);
                } else if (state.opmode === 2) {
                    state.input = bytesToHex(duplicateInput, maxPrintableLength);
                    state.output = bytesToString(duplicateOutput, maxPrintableLength);
                }
            }

            logging(state);

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
                instanceOverload: "[Mac.getInstance(java.lang.String) -> static Mac]",
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
                instanceOverload: "[Mac.getInstance(java.lang.String, java.lang.String) -> static Mac]",
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
                instanceOverload: "[Mac.getInstance(java.lang.String, java.security.Provider) -> static Mac]",
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
                state.initOverload = "[Mac.init(Key key, AlgorithmParameterSpec params) -> void]";
                state.macLength = this.getMacLength();

                logKey(state, key);
            };

            logging(state);
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
                state.initOverload = "[Mac.init(Key key, AlgorithmParameterSpec params) -> void]";
                state.macLength = this.getMacLength();

                logKey(state, key);
                console.log("Params: " + params);
                logAlgorithmParameterSpec(state, params);
            };

            logging(state);
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }

    //  ------------------------
    // | Mac.update() overloads |
    //  ------------------------
    /*
    try { // 1. [Mac.update(byte input) -> void]
        const macKey = Mac.update.overload(
            "byte"
        );

        macKey.implementation = function (input) {
            macKey.call(this, input);

            const objectId = getObjectId("Mac", this);

            let state = macStates.get(objectId);
            
            if (state !== undefined) {
                state.updateCount++;
                state.updates.push({
                    overload: "[Mac.init(byte input) -> void]",
                    input: bytesToHex(input, maxPrintableLength)
                });
            };
        };
    } catch (e) {
        console.log("[+] Error message: " + e.message);
    }
    */

    try { // 2. [Mac.update(byte[] input) -> void]
        const macKey = Mac.update.overload(
            "[B"
        );

        macKey.implementation = function (input) {
            macKey.call(this, input);

            const objectId = getObjectId("Mac", this);

            let state = macStates.get(objectId);

            if (state !== undefined) {
                state.updateOverload = "[Mac.init(byte[] input) -> void]";
                state.updateCount++;
                state.updates.push(bytesToHex(input, maxPrintableLength));
            };
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

            const objectId = getObjectId("Mac", this);

            let state = macStates.get(objectId);

            if (state !== undefined) {
                state.updateOverload = "[Mac.init(byte[] input, int offset, int len) -> void]";
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
                state.finalOverload = "[Mac.doFinal() -> byte[]]";
                state.bytesWritten = output.length;

                if (output !== null) {
                    state.output = bytesToHex(output, maxPrintableLength);
                } else {
                    state.output = "<undefined>";
                }
            };

            logging(state);

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
                state.finalOverload = "[Mac.doFinal(byte[] input) -> byte[]]";
                state.bytesWritten = output.length;
                state.input = bytesToString(input, maxPrintableLength);

                if (output !== null) {
                    state.output = bytesToHex(output, maxPrintableLength);
                } else {
                    state.output = "<undefined>";
                }
            };

            logging(state);

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
                state.finalOverload = "[Mac.doFinal(byte[] output, int outOffset) -> byte[]]";
                state.bytesWritten = output.length;

                if (output !== null) {
                    state.output = bytesToHex(output, outputOffset, output.length, maxPrintableLength);
                } else {
                    state.output = "<undefined>";
                }
            };

            logging(state);

            return outputLen;
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
            lines.push("Input (HEX): " + bytesToHex(input, maxPrintableLength));
            //lines.push("Input (ASCII): " + bytesToString(input, maxPrintableLength));
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
            lines.push("Input (HEX): " + bytesToHexRange(input, offset, len, maxPrintableLength));
            //lines.push("Input (ASCII): " + bytesToStringRange(input, offset, len, maxPrintableLength));
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
            lines.push("Input (HEX): " + bytesToHex(input, maxPrintableLength));
            //lines.push("Input (ASCII): " + bytesToString(input, maxPrintableLength));
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
            lines.push("Input (HEX): " + bytesToHexRange(input, offset, len, maxPrintableLength));
            //lines.push("Input (ASCII): " + bytesToStringRange(input, offset, len, maxPrintableLength));
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
});