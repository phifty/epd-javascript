
(function ($, $$) {
  "use strict";

  var _profileWithoutSignature = function (profile) {
        var result = $.Object.clone(profile);
        delete(result.signature);
        return result;
      };

  $$.sign = function (profile, publicKey, privateKey) {
    return $.Crypt.Asymmetric.sign($.Object.stringify(_profileWithoutSignature(profile)), publicKey, privateKey);
  };

  $$.verify = function (profile, signature, publicKey) {
    return $.Crypt.Asymmetric.verify($.Object.stringify(_profileWithoutSignature(profile)), signature, publicKey);
  };

}(epdRoot,
  epdRoot.Signer = epdRoot.Signer || { }));
