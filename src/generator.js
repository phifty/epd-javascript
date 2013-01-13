
(function ($, $$) {
  "use strict";

  $$.generate = function (keyBits) {
    var id = $.Crypt.Object.generateId()
      , keyPair = $.Crypt.Asymmetric.generateKeyPair(keyBits)
      , profile = {
          id: id,
          publicKey: keyPair.publicKey,
          privateKey: keyPair.privateKey,
          version: 1,
          contacts: { },
          sections: { }
        };

    $.Contacts.add(profile, id, keyPair.publicKey);
    $.Sections.add(profile, undefined, "open");
    $.Sections.add(profile, undefined, "closed");
    $.Modules.add(profile, "open", "build_in:com.anyaku.Basic");

    return profile;
  };

})(epdRoot,
   epdRoot.Generator = epdRoot.Generator || { });
