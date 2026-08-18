const Java = require('frida-java-bridge').default;
rpc.exports = {
    testFunction: function(data) {
        console.log("Received data: " + JSON.stringify(data));
        Java.perform(function() {
            console.log("Java perform within rpc successful");
        });
    }
};
