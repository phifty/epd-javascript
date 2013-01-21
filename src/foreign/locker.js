
(function ($, $$, $$$) {
  "use strict";

  var _dropPrivateKey = function (foreignProfile) {
        delete(foreignProfile.privateKey);
      }

    , _decodePublicKey = function (foreignProfile) {
        foreignProfile.publicKey = $.Crypt.Coder.decode(foreignProfile.publicKey);
      }

    , _decryptContactKeys = function (foreignProfile, profile) {
        $.Iterator.each(foreignProfile.contacts, function (contactId, container) {
          if (profile && profile.publicKey && container.publicKey === $.Crypt.Coder.encode(profile.publicKey)) {
            container.keys =
              $.Crypt.Asymmetric.Object.decrypt(
                $.Crypt.Coder.decode(container.keys), profile.publicKey, profile.privateKey);
            $.Iterator.each(container.keys, function (id, key) {
              container.keys[id] = $.Crypt.Coder.decode(key);
            });
          } else {
            container.publicKey = $.Crypt.Coder.decode(container.publicKey);
            delete(container.keys);
            delete(container.sections);
          }
        });
      }

    , _decryptSections = function (foreignProfile, profile) {
        if (profile && profile.id) {
          var keys = foreignProfile.contacts[profile.id] ? foreignProfile.contacts[profile.id].keys : undefined;
          $.Iterator.each(foreignProfile.sections, function (id, encryptedSection) {
            if ($.Iterator.include($.Sections.openIds, id)) {
              foreignProfile.sections[id] = encryptedSection;
            } else {
              var key = keys ? keys[id] : undefined;
              if (key) {
                foreignProfile.sections[id] = $.Crypt.Symmetric.Object.decrypt($.Crypt.Coder.decode(encryptedSection), key);
              } else {
                delete(foreignProfile.sections[id]);
              }
            }
          });
        }
      };

  $$$.unlock = function (foreignProfile, profile) {
    var result = $.Object.clone(foreignProfile);
    _dropPrivateKey(result);
    _decodePublicKey(result);
    _decryptContactKeys(result, profile);
    _decryptSections(result, profile);
    return result;
  };

})(epdRoot,
   epdRoot.Foreign = epdRoot.Foreign || { },
   epdRoot.Foreign.Locker = epdRoot.Foreign.Locker || { });
