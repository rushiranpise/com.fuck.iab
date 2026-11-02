// author: Fexture69
// TEMPORARY DIAGNOSTIC: does Java.perform work here, and does Premium load?
console.log("[*] Life360 probe: top of script");
Java.perform(function () {
    console.log("[*] Life360 probe: inside perform");
    try {
        var P = Java.use('com.life360.inapppurchase.Premium');
        console.log("[+] Life360 probe: Premium loaded");
    } catch (e) {
        console.log("[-] Life360 probe: Premium " + e);
    }
});
