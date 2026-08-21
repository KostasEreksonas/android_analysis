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

Java.perform(function () {
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
});