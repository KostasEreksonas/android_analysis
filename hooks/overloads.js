'use strict';

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
        const methods = Base64.class.getDeclaredMethods();
        const names = new Set();

        methods.forEach(function (method) {
            names.add(method.getName());
        });

        console.log("\n[+]  ------------------------------------ ");
        console.log("[+] | Base64 methods and their overloads |");
        console.log("[+]  ------------------------------------ ");
        Array.from(names).sort().forEach(function (name) {
            console.log("\n[+] Overloads for Base64." + name + " method:");
            Base64[name].overloads.forEach(function (overload) {
                enumerateOverloads(overload, name);
            });
        });
    } catch (e) {
        console.log("[-] No Base64 hook available.\n[-] Error message:\n[-] " + e.message);
    }

    try {
        const Cipher = Java.use("javax.crypto.Cipher");
        const methods = Cipher.class.getDeclaredMethods();
        const names = new Set();

        methods.forEach(function (method) {
            names.add(method.getName());
        });

        console.log("\n[+]  ------------------------------------ ");
        console.log("[+] | Cipher methods and their overloads |");
        console.log("[+]  ------------------------------------ ");
        Array.from(names).sort().forEach(function (name) {
            console.log("\n[+] Overloads for Cipher." + name + " method:");
            Cipher[name].overloads.forEach(function (overload) {
                enumerateOverloads(overload, name);
            });
        });
    } catch (e) {
        console.log("[-] No Cipher hook available.\n[-] Error message:\n[-] " + e.message);
    }

    try {
        const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        const methods = SecretKeySpec.class.getDeclaredMethods();
        const names = new Set();

        methods.forEach(function (method) {
            names.add(method.getName());
        });

        console.log("\n[+]  ------------------------------------------- ");
        console.log("[+] | SecretKeySpec methods and their overloads |");
        console.log("[+]  ------------------------------------------- ");
        Array.from(names).sort().forEach(function (name) {
            console.log("\n[+] Overloads for SecretKeySpec." + name + " method:");
            SecretKeySpec[name].overloads.forEach(function (overload) {
                enumerateOverloads(overload, name);
            });
        });
    } catch (e) {
        console.log("[-] No SecretKeySpec hook available.\n[-] Error message:\n[-] " + e.message);
    }

    try {
        const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        const methods = IvParameterSpec.class.getDeclaredMethods();
        const names = new Set();

        methods.forEach(function (method) {
            names.add(method.getName());
        });

        console.log("\n[+]  --------------------------------------------- ");
        console.log("[+] | IvParameterSpec methods and their overloads |");
        console.log("[+]  --------------------------------------------- ");
        Array.from(names).sort().forEach(function (name) {
            console.log("\n[+] Overloads for IvParameterSpec." + name + " method:");
            IvParameterSpec[name].overloads.forEach(function (overload) {
                enumerateOverloads(overload, name);
            });
        });
    } catch (e) {
        console.log("[-] No IvParameterSpec hook available.\n[-] Error message:\n[-] " + e.message);
    }

    try {
        const StringsKt = Java.use("kotlin.text.StringsKt");
        const methods = StringsKt.class.getDeclaredMethods();
        const names = new Set();

        methods.forEach(function (method) {
            names.add(method.getName());
        });

        console.log("\n[+]  --------------------------------------- ");
        console.log("[+] | StringsKt methods and their overloads |");
        console.log("[+]  --------------------------------------- ");
        Array.from(names).sort().forEach(function (name) {
            console.log("\n[+] Overloads for StringsKt." + name + " method:");
            StringsKt[name].overloads.forEach(function (overload) {
                enumerateOverloads(overload, name);
            });
        });
    } catch (e) {
        console.log("[-] No StringsKt hook available.\n[-] Error message:\n[-] " + e.message);
    }

    try {
        const MessageDigest = Java.use("java.security.MessageDigest");
        const methods = MessageDigest.class.getDeclaredMethods();
        const names = new Set();

        methods.forEach(function (method) {
            names.add(method.getName());
        });

        console.log("\n[+]  ------------------------------------------- ");
        console.log("[+] | MessageDigest methods and their overloads |");
        console.log("[+]  ------------------------------------------- ");
        Array.from(names).sort().forEach(function (name) {
            console.log("\n[+] Overloads for MessageDigest." + name + " method:");
            MessageDigest[name].overloads.forEach(function (overload) {
                enumerateOverloads(overload, name);
            });
        });
    } catch (e) {
        console.log("[-] No MessageDigest hook available.\n[-] Error message:\n[-] " + e.message);
    }

    try {
        const Mac = Java.use("javax.crypto.Mac");
        const methods = Mac.class.getDeclaredMethods();
        const names = new Set();

        methods.forEach(function (method) {
            names.add(method.getName());
        });

        console.log("\n[+]  --------------------------------- ");
        console.log("[+] | Mac methods and their overloads |");
        console.log("[+]  --------------------------------- ");
        Array.from(names).sort().forEach(function (name) {
            console.log("\n[+] Overloads for Cipher." + name + " method:");
            Mac[name].overloads.forEach(function (overload) {
                enumerateOverloads(overload, name);
            });
        });
    } catch (e) {
        console.log("[-] No Mac hook available.\n[-] Error message:\n[-] " + e.message);
    }
});