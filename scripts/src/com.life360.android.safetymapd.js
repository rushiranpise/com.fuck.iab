var Premium = null;
try { Premium = Java.use('com.life360.inapppurchase.Premium'); } catch (e) { console.log(`[-] Premium: ${e}`); }

if (Premium) {
    // Probe skuInfoForCircle: only fake paid state if the real call succeeds.
    var skuInfoWorks = false;
    try {
        var probe = Premium.skuInfoForCircle.overload('java.lang.String');
        // can't invoke without an instance; just check overload exists
        skuInfoWorks = (probe !== undefined);
    } catch (e) { skuInfoWorks = false; }

    // Do NOT hook skuInfoForCircle. Leave it to the real implementation.
    // Only override the flags that depend on the real skuInfo.
    if (skuInfoWorks) {
        try {
            Premium.skuForCircle.overload('java.lang.String').implementation =
                guard('Premium.skuForCircle', function () { return "9"; },
                    function (cid) { return Premium.skuForCircle.call(this, cid); });
        } catch (e) { console.log(`[-] skuForCircle: ${e}`); }

        try {
            var PS2 = Java.use('com.life360.inapppurchase.PaymentState');
            Premium.paymentStateForCircle.overload('java.lang.String').implementation =
                guard('Premium.paymentStateForCircle', function () { return PS2.PAID.value; },
                    function (cid) { return Premium.paymentStateForCircle.call(this, cid); });
        } catch (e) { console.log(`[-] paymentStateForCircle: ${e}`); }
    } else {
        console.log("[!] skuInfoForCircle unavailable – skipping paid-flag overrides to avoid contradiction.");
    }

    try {
        var MTE = Java.use('com.life360.inapppurchase.MembershipTierExperience');
        Premium.membershipTierExperience.implementation =
            guard('Premium.membershipTierExperience', function () { return MTE.TRIPLE_TIER.value; },
                function () { return this.membershipTierExperience(); });
    } catch (e) { console.log(`[-] membershipTierExperience: ${e}`); }

    try {
        Premium.trialForSku.overload('java.lang.String').implementation =
            guard('Premium.trialForSku', function () { return Java.use('java.lang.Integer').$new(7); },
                function (s) { return Premium.trialForSku.call(this, s); });
    } catch (e) { console.log(`[-] trialForSku: ${e}`); }
}