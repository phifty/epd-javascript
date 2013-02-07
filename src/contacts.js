
(function ($, $$) {
  "use strict";

  $$.ids = function (profile) {
    var ids = [ ];
    $.Iterator.each(profile.contacts, function (id) {
      if (profile.id !== id) {
        ids.push(id);
      }
    });
    return ids;
  };

  $$.idsBySectionId = function (profile, sectionId) {
    return $.Iterator.select($$.ids(profile), function (index, id) {
      return !!profile.contacts[id].keys[sectionId];
    });
  };

  $$.publicKeyForContactId = function (profile, contactId) {
    return profile.contacts[contactId].publicKey;
  };

  $$.keysForContactId = function (profile, contactId) {
    return profile.contacts[contactId].keys;
  };

  $$.keyForContactIdAndSectionId = function (profile, contactId, sectionId) {
    return profile.contacts[contactId].keys[sectionId];
  };

  $$.add = function (profile, id, publicKey) {
    var contacts = profile.contacts;

    if (contacts[id]) {
      return profile;
    }

    contacts[id] = {
      publicKey: publicKey,
      keys: { }
    };

    if (profile.id !== id) {
      contacts[id].sections = [ ];
    }

    return profile;
  };

  $$.remove = function (profile, id) {
    delete(profile.contacts[id]);
    return profile;
  };

  $$.ensureAdded = function (profile, ids, profileGetFunction) {
    var contactIds = $$.ids(profile);

    $.Iterator.each(ids, function (_, id) {
      var contactProfile = profileGetFunction(id);
      if (contactProfile && !$.Iterator.include(contactIds, id)) {
        profile = $$.add(profile, contactProfile.id, contactProfile.publicKey);
      }
    });

    return profile;
  };

  $$.ensureRemoved = function (profile, ids) {
    var contactIds = $$.ids(profile);

    $.Iterator.each(ids, function (_, id) {
      if ($.Iterator.include(contactIds, id)) {
        profile = $$.remove(profile, id);
      }
    });

    return profile;
  };

}(epdRoot,
  epdRoot.Contacts = epdRoot.Contacts || { }));
