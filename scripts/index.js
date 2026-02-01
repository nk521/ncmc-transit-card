import Java from "frida-java-bridge";

var libapp = null;

function tryLoadLibapp() {
    try {
        libapp = Module.findBaseAddress('libapp.so');
    } catch (e) {
        if (e instanceof TypeError && e.message === "not a function") {
            libapp = Process.findModuleByName('libapp.so');
            if (libapp != null) {
                libapp = libapp.base;
            }
        } else {
            throw e;
        }
    }
    if (libapp === null)
        setTimeout(tryLoadLibapp, 500);
    else
        onLibappLoaded()
}

function onLibappLoaded() {
    const jmp = libapp.add(0x7242b4);
    Memory.patchCode(jmp, 4, code => {
        const cw = new Arm64Writer(code, { pc: jmp });
        cw.putBImm(libapp.add(0x7242c8));
        cw.flush();
    });
}

Java.performNow(function () {
});

Java.perform(function () {

    const Log = Java.use('android.util.Log');
    const Exception = Java.use('java.lang.Exception');
    function stackTraceHere() {
        return Log.getStackTraceString(Exception.$new());
    }

    var BuildConfig = Java.use("com.pinelabs.bharatyatra.BuildConfig");
    BuildConfig.DEBUG.value = true;

    var MainActivity = Java.use("com.pinelabs.bharatyatra.MainActivity");
    var GoogleApiAvailability = Java.use("com.google.android.gms.common.GoogleApiAvailability");

    MainActivity["checkDeviceSecurity"].implementation = function () {
        return false;
    };

    MainActivity["verifyAppSignature"].implementation = function () {
        return true;
    };

    MainActivity["showTamperingAlert"].implementation = function () {
        return;
    };

    GoogleApiAvailability["isGooglePlayServicesAvailable"].overload('android.content.Context').implementation = function (context) {
        return 0;
    };
    
    tryLoadLibapp();
});
