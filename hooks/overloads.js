'use strict';
/*

Discover existing overloads for a given method

*/
function enumerateOverloads(overload, name) {
    console.log(
        "[+]\t" + name + "(" + overload.argumentTypes.map(
            function (type) {
                return type.className;
            }
        ).join(", ") + ") -> " + overload.returnType.className
    );
}

Java.perform(function () {
    try {
        const Base64 = Java.use("android.util.Base64");

        console.log("\n[+] Overloads for Base64.decode method:");
        Base64.decode.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "decode");
        });

        console.log("\n[+] Overloads for Base64.encodeToString method:");
        Base64.encodeToString.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "encodeToString");
        });
    } catch (e) {
        console.log("[-] No Base64 hook available.\n[-] Error message:\n[-] " + e.message);
    }

    try {
        const Cipher = Java.use("javax.crypto.Cipher");

        console.log("\n[+] Overloads for Cipher.getInstance method:");
        Cipher.getInstance.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "getInstance");
        });

        console.log("\n[+] Overloads for Cipher.init method:");    
        Cipher.init.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "init");
        });

        console.log("\n[+] Overloads for Cipher.doFinal method:");    
        Cipher.doFinal.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "doFinal");
        });
    } catch (e) {
        console.log("[-] No Cipher hook available.\n[-] Error message:\n[-] " + e.message);
    }
    
    try {
        const SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');

        console.log("\n[+] Overloads for SecretKeySpec.$init method:");    
        SecretKeySpec.$init.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "$init");
        });
    } catch (e) {
        console.log("[-] No SecretKeySpec hook available.\n[-] Error message:\n[-] " + e.message);
    }

    try {
        const IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');

        console.log("\n[+] Overloads for IvParameterSpec.$init method:");    
        IvParameterSpec.$init.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "$init");
        });
    } catch (e) {
        console.log("[-] No IvParameterSpec hook available.\n[-] Error message:\n[-] " + e.message);
    }

    try {
        const StringsKt = Java.use('kotlin.text.StringsKt');

        console.log("\n[+] Overloads for StringsKt.encodeToByteArray method:")
        StringsKt.encodeToByteArray.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "encodeToByteArray");
        });
    
        console.log("\n[+] Overloads for StringsKt.decodeToString method:")
        StringsKt.decodeToString.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "decodeToString");
        });
    } catch (e) {
        console.log("[-] No StringsKt hook available.\n[-] Error message:\n[-] " + e.message);
    }

    try {
        const MessageDigest = Java.use('java.security.MessageDigest');

        console.log("\n[+] Overloads for MessageDigest.getInstance method:")
        MessageDigest.getInstance.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "getInstance");
        });
        
        console.log("\n[+] Overloads for MessageDigest.update method:")
        MessageDigest.update.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "update");
        });
        
        console.log("\n[+] Overloads for MessageDigest.digest method:")
        MessageDigest.digest.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "digest");
        });
    } catch (e) {
        console.log("[-] No MessageDigest hook available.\n[-] Error message:\n[-] " + e.message);
    }

    try {
        const Mac = Java.use('javax.crypto.Mac');

        console.log("\n[+] Overloads for Mac.init method:")
        Mac.init.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "init");
        });

        console.log("\n[+] Overloads for Mac.update method:")
        Mac.update.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "update");
        });
        
        console.log("\n[+] Overloads for Mac.doFinal method:")
        Mac.doFinal.overloads.forEach(function (overload) {
            enumerateOverloads(overload, "doFinal");
        });
    } catch (e) {
        console.log("[-] No Mac hook available.\n[-] Error message:\n[-] " + e.message);
    }
});