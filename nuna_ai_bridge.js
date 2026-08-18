const Java = require('frida-java-bridge').default;

function log(msg) {
    send({"type": "log", "payload": msg});
}

rpc.exports = {
    processHeartRate: function(jsonData) {
        if (!Java.available) {
            log("Java is not available inside processHeartRate!");
            return;
        }

        Java.perform(function() {
            try {
                var AiEngineUtil = Java.use("com.xthings.nuna.model.nunaaiengine.util.AiEngineUtil");
                var instance = AiEngineUtil.INSTANCE.value;
                instance.processHeartRateData(jsonData);
            } catch(e) {
                send({"type": "error", "error": e.toString()});
            }
        });
    }
};

function trySetup() {
    Java.perform(function() {
        log("Java is available! Bypassing splash and launching MainActivity...");
        
        try {
            var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
            var context = currentApplication.getApplicationContext();
            
            var intent = Java.use("android.content.Intent").$new();
            var component = Java.use("android.content.ComponentName").$new("com.xthings.nuna", "com.xthings.nuna.main.view.MainActivity");
            intent.setComponent(component);
            intent.setFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK
            
            context.startActivity(intent);
            log("Started MainActivity successfully!");
        } catch(e) {
            log("Exception starting MainActivity: " + e);
        }

        var attempts = 0;
        function checkEngine() {
            attempts++;
            Java.perform(function() {
                try {
                    var AiEngineUtil = Java.use("com.xthings.nuna.model.nunaaiengine.util.AiEngineUtil");
                    // In Kotlin, the singleton might just be accessed via INSTANCE field
                    var instance = AiEngineUtil.INSTANCE.value;
                    if (instance != null) {
                        log("AiEngineUtil instance found!");
                        if (!instance.isEngineValid()) {
                            log("Forcing AI Engine Initialization...");
                            instance.initEngineWithInstalledPacksAsync("US");
                            instance.registerHeartRateBatchCallbackOnce();
                            log("Engine initialized!");
                        }
                        
                        var HeartRateManager = Java.use("com.xthings.nuna.model.nunaaiengine.HeartRateManager");
                        HeartRateManager.dispatchLatest.implementation = function(item) {
                            if (item != null) {
                                try {
                                    var hr = item.getHr();
                                    var ts = item.getTimestamp();
                                    send({"type": "heart_rate", "hr": hr, "timestamp": ts});
                                } catch(e) {
                                    log("Error reading HR item: " + e.toString());
                                }
                            }
                            return this.dispatchLatest(item);
                        };
                        log("Hooked HeartRateManager successfully!");
                    } else {
                        if (attempts < 60) {
                            setTimeout(checkEngine, 1000);
                        } else {
                            log("AiEngineUtil never initialized after 60 seconds.");
                        }
                    }
                } catch(e) {
                    log("Check engine failed: " + e.toString());
                    if (attempts < 60) {
                        setTimeout(checkEngine, 1000);
                    }
                }
            });
        }
        
        // Wait 2 seconds for MainActivity to breathe, then start polling
        setTimeout(checkEngine, 2000);
    });
}

trySetup();
