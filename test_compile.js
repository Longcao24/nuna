const Java = require('frida-java-bridge').default;
Java.perform(function() {
    console.log("Java perform successful");
});
