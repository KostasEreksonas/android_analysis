'use strict';

const maxPrintableLength = 48; // Limit length of logged hex and ascii strings
const Log = Java.use("android.util.Log");
const Throwable = Java.use("java.lang.Throwable");

function traceStack() {
    return Log.getStackTraceString(Throwable.$new());
}

function logging(state) {
    console.log(JSON.stringify(state, null, 2));
}

function fingerprint(input, type, bufferOffset, bufferLength) {
    // Compute a 32-bit FNV-1a hash
    if (input === null || input === undefined) return "<null>";
    
    const start = (bufferOffset === undefined || bufferLength === undefined) ? 0 : bufferOffset;
    const end = (bufferOffset === undefined || bufferLength === undefined) ? input.length : bufferOffset + bufferLength;

    let h = 2166136261;
    for (let i = start; i < end; i++) {
        if (type === "object") {
            h ^= (input[i] & 0xFF);
        } else if (type === "string") {
            h ^= (input.toString().charCodeAt(i) & 0xFF);
        }

        h = Math.imul(h, 16777619);
    }

    return (h >>> 0).toString(16).padStart(8, "0") + ":" + input.length;
}

function bytesToHex(bytes, maxLength, bufferOffset, bufferLength) {
    if (bytes === null || bytes === undefined) return "<null>";

    let result = "";

    const start = (bufferOffset === undefined || bufferLength === undefined) ? 0 : bufferOffset;
    const end = (bufferOffset === undefined || bufferLength === undefined) ? bytes.length : bufferOffset + bufferLength;
    const length = end - start;
    const hasLimit = typeof maxLength === "number" && maxLength > 0; // If maxLength === 0, parse whole byte array
    const len = hasLimit ? Math.min(maxLength, length) : length; // Truncate the log entry if maxLength < bytes.length

    for (let i = start; i < (start + len); i++) {
        let v = bytes[i];
        if (v < 0) v += 256;
        result += ("0" + v.toString(16)).slice(-2);
    }

    if (hasLimit && length > len) result += ` ... [${length - len} more bytes]`;

    return result;
}

function bytesToString(bytes, maxLength, bufferOffset, bufferLength) {
    if (bytes === null || bytes === undefined) return "<null>";

    let result = "";

    const start = (bufferOffset === undefined || bufferLength === undefined) ? 0 : bufferOffset;
    const end = (bufferOffset === undefined || bufferLength === undefined) ? bytes.length : bufferOffset + bufferLength;
    const length = end - start;
    const hasLimit = typeof maxLength === "number" && maxLength > 0; // If maxLength === 0, parse whole byte array
    const len = hasLimit ? Math.min(maxLength, length) : length; // Truncate the log entry if maxLength < bytes.length

    for (let i = start; i < (start + len); ++i) {
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

    if (hasLimit && length > len) result += ` ... [${length - len} more bytes]`;

    return result;
}

function logKey(state, key) {
    if (key === null) return;

    state.keyClass = key.$className;
    state.keyAlgorithm = key.getAlgorithm();
    state.keyFormat = key.getFormat();

    const encoded = key.getEncoded();

    if (encoded !== null) {
        state.keyBytesHex = bytesToHex(encoded, maxPrintableLength);
        state.keyBytesString = bytesToString(encoded, maxPrintableLength);
        state.keyBytesFingerprint = fingerprint(encoded, typeof(encoded));
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
        state.parameterEncoded = bytesToHex(params.getEncoded(), 0, 0, maxPrintableLength);
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
        const ivValue = ivSpec.getIV();

        state.iv = bytesToHex(ivValue, 0, 0, maxPrintableLength);
        state.ivFingerprint = fingerprint(ivValue, typeof(ivValue));
    }

    if (params.$className === "javax.crypto.spec.GCMParameterSpec") {
        const GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
        const gcm = Java.cast(params, GCMParameterSpec);

        state.gcmIv = bytesToHex(gcm.getIV(), 0, 0, maxPrintableLength);
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
    } else {
        return "UNKNOWN";
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
}

function truncateBase64(str) {
    // Truncate a Base64 string returned by java.lang.String objet
    let truncated;

    if (str.length > maxPrintableLength) {
        truncated = str.substring(0, maxPrintableLength);
        truncated += ` ... [${str.length - maxPrintableLength} more bytes]`;
    } else {
        truncated = str;
    }

    return truncated;
}

function resetDigestState(state) {
    state.updateInputs = [];
    state.updateInputsString = [];
    state.updateInputsLen = [];
}

Java.perform(function () {
    const messageDigestStates = new Map();
    //  -------------------------
    // | MessageDigest overloads |
    //  -------------------------
    const MessageDigest = Java.use("java.security.MessageDigest");

    //  ---------------------------------------
    // | MessageDigest.getInstance() overloads |
    //  ---------------------------------------
    try {// 1. [MessageDigest.getInstance(java.lang.String) -> static MessageDigest]
        const instanceKey = MessageDigest.getInstance.overload(
            "java.lang.String"
        );

        instanceKey.implementation = function (transformation) {
            const digest = instanceKey.call(MessageDigest, transformation);
            const provider = digest.getProvider();
            const objectId = getObjectId("MessageDigest", digest);

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                lastSeen: Date.now(),
                instanceOverload: "1. [MessageDigest.getInstance(java.lang.String) -> static MessageDigest]",
                transformation: transformation,
                algorithm: digest.getAlgorithm(),
                runtimeClass: digest.getClass().getName(),
                providerName: provider.getName(),
                providerVersion: provider.getVersion(),
                providerInfo: provider.getInfo(),
                providerClass: provider.getClass().getName(),
                updateInputs: [],
                updateInputsString: [],
                updateInputsLen: [],
            };

            messageDigestStates.set(objectId, state);

            return digest;
        }
    } catch (e) {
        console.log("[+] ERROR - 1. [MessageDigest.getInstance(java.lang.String) -> static MessageDigest]: " + e.message);
    }

    try { // 2. [MessageDigest.getInstance(String transformation, String provider) -> static MessageDigest]
        const instanceKey = MessageDigest.getInstance.overload(
            "java.lang.String",
            "java.lang.String"
        );

        instanceKey.implementation = function (transformation, provider) {
            const digest = instanceKey.call(MessageDigest, transformation, provider);
            const digestProvider = digest.getProvider();
            const objectId = getObjectId("MessageDigest", digest);

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                lastSeen: Date.now(),
                instanceOverload: "2. [MessageDigest.getInstance(String transformation, String provider) -> static MessageDigest]",
                transformation: transformation,
                algorithm: digest.getAlgorithm(),
                runtimeClass: digest.getClass().getName(),
                providerName: digestProvider.getName(),
                providerVersion: digestProvider.getVersion(),
                providerInfo: digestProvider.getInfo(),
                providerClass: digestProvider.getClass().getName(),
                updateInputs: [],
                updateInputsString: [],
                updateInputsLen: [],
            };

            messageDigestStates.set(objectId, state);

            return digest;
        };
    } catch (e) {
        console.log("[+] ERROR - 2. [MessageDigest.getInstance(String transformation, String provider) -> static MessageDigest]: " + e.message);
    }

    try { // 3. [MessageDigest.getInstance(String transformation, Provider provider) -> static MessageDigest]
        const instanceKey = MessageDigest.getInstance.overload(
            "java.lang.String",
            "java.security.Provider"
        );

        instanceKey.implementation = function (transformation, provider) {
            const digest = instanceKey.call(MessageDigest, transformation, provider);
            const objectId = getObjectId("MessageDigest", digest);

            const state = {
                objectId: objectId,
                timestamp: Date.now(),
                lastSeen: Date.now(),
                instanceOverload: "3. [MessageDigest.getInstance(String transformation, Provider provider) -> static MessageDigest]",
                transformation: transformation,
                algorithm: digest.getAlgorithm(),
                runtimeClass: digest.getClass().getName(),
                providerName: provider.getName(),
                providerVersion: provider.getVersion(),
                providerInfo: provider.getInfo(),
                providerClass: provider.getClass().getName(),
                updateInputs: [],
                updateInputsString: [],
                updateInputsLen: [],
            };

            messageDigestStates.set(objectId, state);

            return digest;
        };
    } catch (e) {
        console.log("[+] ERROR - 3. [MessageDigest.getInstance(String transformation, Provider provider) -> static MessageDigest]: " + e.message);
    }

    //  ----------------------------------
    // | MessageDigest.update() overloads |
    //  ----------------------------------
    try { // 1. [MessageDigest.update(byte[] input) -> void]
        const digestKey = MessageDigest.update.overload(
            "[B"
        );

        digestKey.implementation = function (input) {
            digestKey.call(this, input);

            const objectId = getObjectId("MessageDigest", this);
            let state = messageDigestStates.get(objectId);

            if (state !== undefined) {
                state.updateOverload = "1. [MessageDigest.update(byte[] input) -> void]";
                state.updateInputs.push(bytesToHex(input, maxPrintableLength));
                state.updateInputsLen.push(input.length);
                state.lastSeen = Date.now();
            }
        };
    } catch (e) {
        console.log("[+] ERROR - 1. [MessageDigest.update(byte[] input) -> void]: " + e.message);
    }

    try { // 2. [MessageDigest.update(byte[] input, int offset, int len) -> void]
        const digestKey = MessageDigest.update.overload(
            "[B",
            "int",
            "int"
        );

        digestKey.implementation = function (input, offset, len) {
            digestKey.call(this, input, offset, len);

            const objectId = getObjectId("MessageDigest", this);
            let state = messageDigestStates.get(objectId);
            let length = len - offset;

            if (state !== undefined) {
                state.updateOverload = "2. [MessageDigest.update(byte[] input, int offset, int len) -> void]";
                state.updateInputs.push(bytesToHex(input, maxPrintableLength, offset, len));
                state.updateInputsLen.push(length);
                state.lastSeen = Date.now();
            }
        };
    } catch (e) {
        console.log("[+] ERROR - 2. [MessageDigest.update(byte[] input, int offset, int len) -> void]: " + e.message);
    }

    //  ----------------------------------
    // | MessageDigest.digest() overloads |
    //  ----------------------------------
    try { // 1. [MessageDigest.digest() -> byte[]]
        const digestKey = MessageDigest.digest.overload();

        digestKey.implementation = function () {
            const output = digestKey.call(this);
            const objectId = getObjectId("MessageDigest", this);
            let state = messageDigestStates.get(objectId);

            if (state !== undefined) {
                state.digestOverload = "1. [MessageDigest.digest() -> byte[]]";

                if (output !== null) {
                    state.digestedHash = bytesToHex(output, 0, 0, maxPrintableLength);
                    state.digestedHashLength = output.length;
                    state.digestedHashFingerprint = fingerprint(output, typeof(output));
                    state.lastSeen = Date.now();
                }

                logging(state);
                resetDigestState(state);
            }

            return output;
        };
    } catch (e) {
        console.log("[+] ERROR - 1. [MessageDigest.digest() -> byte[]]: " + e.message);
    }

    try { // 2. [MessageDigest.digest(byte[] input) -> byte[]]
        const digestKey = MessageDigest.digest.overload(
            "[B"
        );

        digestKey.implementation = function (input) {
            const output = digestKey.call(this, input);
            const objectId = getObjectId("MessageDigest", this);
            let state = messageDigestStates.get(objectId);

            if (state !== undefined) {
                state.digestOverload = "2. [MessageDigest.digest(byte[] input) -> byte[]]";
                state.updateInputs.push(bytesToHex(input, maxPrintableLength));
                state.updateInputsLen.push(input.length);

                if (output !== null) {
                    state.digestedHash = bytesToHex(output, maxPrintableLength);
                    state.digestedHashLength = output.length;
                    state.digestedHashFingerprint = fingerprint(output, typeof(output));
                    state.lastSeen = Date.now();
                }

                logging(state);
                resetDigestState(state);
            }

            return output;
        };
    } catch (e) {
        console.log("[+] ERROR - 2. [MessageDigest.digest(byte[] input) -> byte[]]: " + e.message);
    }

    try { // 3. [MessageDigest.digest(byte[] buf, int offset, int len) -> int]
        const digestKey = MessageDigest.digest.overload(
            "[B",
            "int",
            "int"
        );

        digestKey.implementation = function (outputBuf, offset, len) {
            const outputLen = digestKey.call(this, outputBuf, offset, len);
            const objectId = getObjectId("MessageDigest", this);
            let state = messageDigestStates.get(objectId);

            if (state !== undefined) {
                state.digestOverload = "3. [MessageDigest.digest(byte[] input, int offset, int len) -> int]";

                if (outputLen > 0) {
                    state.digestedHash = bytesToHex(outputBuf, offset, outputLen, maxPrintableLength);
                    state.digestedHashLength = outputLen;
                    state.digestedHashFingerprint = fingerprint(outputBuf, typeof(outputBuf), offset, outputLen);
                    state.lastSeen = Date.now();
                } else {
                    state.digestedHash = "";
                    state.digestedHashLength = 0;
                    state.digestedHashFingerprint = fingerprint(outputBuf, typeof(outputBuf), offset, outputLen);
                    state.lastSeen = Date.now();
                }

                logging(state);
                resetDigestState(state);
            }

            return outputLen;
        };
    } catch (e) {
        console.log("[+] ERROR - 3. [MessageDigest.digest(byte[] input, int offset, int len) -> int]: " + e.message);
    }

    //  --------------------------------
    // | MessageDigest.reset() overload |
    //  --------------------------------
    try { // 1. [MessageDigest.reset() -> void]
        const digestKey = MessageDigest.reset.overload();

        digestKey.implementation = function () {
            digestKey.call(this);

            const objectId = getObjectId("MessageDigest", this);
            let state = messageDigestStates.get(objectId);

            if (state !== undefined) {
                state.resetOverload = "1. [MessageDigest.reset() -> void]";
                state.resetCount = (state.resetCount || 0) + 1;
                state.discardedUpdateInputs = state.updateInputs.slice();
                state.discardedUpdateInputsLen = state.updateInputsLen.slice();
                state.lastSeen = Date.now();

                logging(state);
                resetDigestState(state);
            }
        };
    } catch (e) {
        console.log("[+] ERROR - 1. [MessageDigest.reset() -> void]: " + e.message);
    }
});