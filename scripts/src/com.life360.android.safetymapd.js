// author: Fexture69
// The whole script runs inside Java.perform so the app's class loader is bound before any
// Java.use call. Outside it the lookup happens too early and the class is not found.
Java.perform(function () {
    var Premium = null;
    try { Premium = Java.use('com.life360.inapppurchase.Premium'); } catch (e) { console.log(`[-] Premium: ${e}`); }

    // values() forces <clinit>, so an enum is never read before it is initialised.
    function enumValue(className, constantName) {
        var values = Java.use(className).values();

        for (var i = 0; i < values.length; i++) {
            if (values[i].name().toString() === constantName) return values[i];
        }

        return null;
    }

    // Runs the override, and falls back to the real method if it throws, so a missing
    // enum constant can never hand the app a null where it expects an object.
    function guard(name, fake, original) {
        return function () {
            try {
                return fake.apply(this, arguments);
            } catch (e) {
                console.log(`[-] ${name}: ${e}, using the real method`);
                return original.apply(this, arguments);
            }
        };
    }

    if (Premium) {
        // Probe skuInfoForCircle: only fake paid state if the real call succeeds.
        var skuInfoWorks = false;
        try {
            skuInfoWorks = Premium.skuInfoForCircle.overload('java.lang.String') !== undefined;
        } catch (e) { skuInfoWorks = false; }

        // Do NOT hook skuInfoForCircle. Leave it to the real implementation.
        // Only override the flags that depend on the real skuInfo.
        if (skuInfoWorks) {
            try {
                Premium.skuForCircle.overload('java.lang.String').implementation =
                    guard('Premium.skuForCircle', function () { return "9"; },
                        function (cid) { return this.skuForCircle(cid); });
            } catch (e) { console.log(`[-] skuForCircle: ${e}`); }

            try {
                Premium.paymentStateForCircle.overload('java.lang.String').implementation =
                    guard('Premium.paymentStateForCircle', function () {
                        var paid = enumValue('com.life360.inapppurchase.PaymentState', 'PAID');
                        if (paid == null) throw new Error('PaymentState.PAID not found');
                        return paid;
                    }, function (cid) { return this.paymentStateForCircle(cid); });
            } catch (e) { console.log(`[-] paymentStateForCircle: ${e}`); }
        } else {
            console.log("[!] skuInfoForCircle unavailable - skipping paid-flag overrides to avoid contradiction.");
        }

        try {
            Premium.membershipTierExperience.implementation =
                guard('Premium.membershipTierExperience', function () {
                    var tier = enumValue('com.life360.inapppurchase.MembershipTierExperience', 'TRIPLE_TIER');
                    if (tier == null) throw new Error('MembershipTierExperience.TRIPLE_TIER not found');
                    return tier;
                }, function () { return this.membershipTierExperience(); });
        } catch (e) { console.log(`[-] membershipTierExperience: ${e}`); }

        try {
            Premium.trialForSku.overload('java.lang.String').implementation =
                guard('Premium.trialForSku', function () { return Java.use('java.lang.Integer').$new(7); },
                    function (sku) { return this.trialForSku(sku); });
        } catch (e) { console.log(`[-] trialForSku: ${e}`); }
    } else {
        console.log("[-] Premium class not found, nothing hooked");
    }

    console.log("[*] Script finished loading.");
});
