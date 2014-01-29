
(function ($, $$) {
  "use strict";

  var _encryptSections = function (profile) {
        $.Iterator.each(profile.sections, function (id, section) {
          if ($.Collection.include($.Sections.openIds, id)) {
            profile.sections[id] = section;
          } else {
            var key = $.Sections.findKey(profile.contacts, id);
            profile.sections[id] = $.Crypt.Coder.encode(
                                    $.Crypt.Symmetric.Object.encrypt(section, key));
          }
        });
      }

    , _encryptContactKeys = function (profile, closedSectionKey, publicKeyResolver) {
        $.Iterator.each(profile.contacts, function (contactId, contact) {
          var publicKey = publicKeyResolver(contactId);
          if (publicKey) {
            var keys = contact.keys;
            if (keys) {
              $.Iterator.each(keys, function (id, key) {
                keys[id] = $.Crypt.Coder.encode(key);
              });
              contact.keys = $.Crypt.Coder.encode(
                $.Crypt.Asymmetric.Object.encrypt(keys, publicKey));
            }

            // fix for old profiles that still have this obsolete sections key
            if (contactId === profile.id) {
              delete(contact.sections);
            }

            if (contact.sections) {
              contact.sections = $.Crypt.Coder.encode(
                $.Crypt.Symmetric.Object.encrypt(contact.sections, closedSectionKey));
            }
          }
        });
      }

    , _encryptPrivateKey = function (profile, password) {
        var encodedPrivateKey = $.Crypt.Coder.encode(profile.privateKey)
          , encryptedPrivateKey = $.Crypt.Symmetric.encrypt(encodedPrivateKey, password.hash)
          , encodedEncryptedPrivateKey = $.Crypt.Coder.encode(encryptedPrivateKey)
          , encodedSalt = $.Crypt.Coder.encode(password.salt);

        profile.privateKey = {
          encrypted: encodedEncryptedPrivateKey,
          salt: encodedSalt,
          keySize: password.keySize,
          iterations: password.iterations
        };
      }

    , _encodePublicKey = function (profile) {
        profile.publicKey = $.Crypt.Coder.encode(profile.publicKey);
      }

    , _sign = function (profile, publicKey, privateKey) {
        profile.signature = $.Crypt.Coder.encode($.Signer.sign(profile, publicKey, privateKey));
      }

    , _verify = function (profile, publicKey) {
        if (!profile.signature) {
          throw(new Error("missing profile signature"));
        }
        var signature = $.Crypt.Coder.decode(profile.signature);
        if (!$.Signer.verify(profile, signature, publicKey)) {
          throw(new Error("invalid profile signature"));
        }
      }

    , _decodePublicKey = function (profile) {
        profile.publicKey = $.Crypt.Coder.decode(profile.publicKey);
      }

    , _decryptPrivateKey = function (profile, password) {
        try {
          var decodedEncryptedPrivateKey = $.Crypt.Coder.decode(profile.privateKey.encrypted)
            , decryptedPrivateKey = $.Crypt.Symmetric.decrypt(decodedEncryptedPrivateKey, password.hash);

          profile.privateKey = $.Crypt.Coder.decode(decryptedPrivateKey);
        } catch (error) {
          throw(/^Malformed/.exec(error.message) || /^Type.+not supported!$/.exec(error.message) ?
            new Error("invalid password") : error);
        }
      }

    , _decryptOwnContactKeys = function (profile) {
        var contact = profile.contacts[profile.id];
        contact.keys = $.Crypt.Asymmetric.Object.decrypt(
                         $.Crypt.Coder.decode(contact.keys), profile.publicKey, profile.privateKey);
        $.Iterator.each(contact.keys, function (id, key) {
          contact.keys[id] = $.Crypt.Coder.decode(key);
        });
      }

    , _decryptContactKeys = function (profile, closedSectionKey) {
        $.Iterator.each(profile.contacts, function (id, contact) {
          if (id !== profile.id) {
            if (contact.sections) {
              contact.sections = $.Crypt.Symmetric.Object.decrypt(
                                   $.Crypt.Coder.decode(contact.sections), closedSectionKey);
            }
            contact.keys = { };
            $.Iterator.each(contact.sections, function (index, sectionId) {
              contact.keys[sectionId] = $.Sections.findKey(profile.contacts, sectionId);
            });
          }
        });
      }

    , _decryptSections = function (profile) {
        var keys = profile.contacts[profile.id] ? profile.contacts[profile.id].keys : undefined;
        if (!keys) { return; }
        $.Iterator.each(profile.sections, function (id, encryptedSection) {
          if ($.Collection.include($.Sections.openIds, id)) {
            profile.sections[id] = encryptedSection;
          } else {
            var key = keys[id];
            profile.sections[id] = key ?
              $.Crypt.Symmetric.Object.decrypt($.Crypt.Coder.decode(encryptedSection), key) :
              undefined;
          }
        });
      };

  $$.lock = function (unlockedProfile, password, publicKeyResolver) {
    var profile = $.Object.clone(unlockedProfile);
    _encryptSections(profile);
    _encryptContactKeys(profile, $.Sections.findKey(unlockedProfile.contacts, "closed"), publicKeyResolver);
    _encryptPrivateKey(profile, password);
    _encodePublicKey(profile);
    _sign(profile, unlockedProfile.publicKey, unlockedProfile.privateKey);
    return profile;
  };

  $$.unlock = function (lockedProfile, password) {
    var profile = $.Object.clone(lockedProfile);
    _verify(profile, $.Crypt.Coder.decode(lockedProfile.publicKey));
    _decodePublicKey(profile);
    _decryptPrivateKey(profile, password);
    _decryptOwnContactKeys(profile);
    _decryptContactKeys(profile, $.Sections.findKey(profile.contacts, "closed"));
    _decryptSections(profile);
    return profile;
  };

})(epdRoot,
   epdRoot.Locker = epdRoot.Locker || { });
