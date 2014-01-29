
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
    return $.Collection.select($$.ids(profile), function (index, id) {
      return !!profile.contacts[id].keys[sectionId];
    });
  };

  $$.keysForContactId = function (profile, contactId) {
    return profile.contacts[contactId].keys;
  };

  $$.keyForContactIdAndSectionId = function (profile, contactId, sectionId) {
    return profile.contacts[contactId].keys[sectionId];
  };

  $$.add = function (profile, id) {
    var contacts = profile.contacts;

    if (contacts[id]) {
      return profile;
    }

    contacts[id] = { keys: { } };

    if (profile.id !== id) {
      contacts[id].sections = [ ];
    }

    return profile;
  };

  $$.remove = function (profile, id) {
    delete(profile.contacts[id]);
    return profile;
  };

  $$.ensureAdded = function (profile, ids) {
    var contactIds = $$.ids(profile);

    $.Iterator.each(ids, function (_, id) {
      if (!$.Collection.include(contactIds, id)) {
        profile = $$.add(profile, id);
      }
    });

    return profile;
  };

  $$.ensureRemoved = function (profile, ids) {
    var contactIds = $$.ids(profile);

    $.Iterator.each(ids, function (_, id) {
      if ($.Collection.include(contactIds, id)) {
        profile = $$.remove(profile, id);
      }
    });

    return profile;
  };

}(epdRoot,
  epdRoot.Contacts = epdRoot.Contacts || { }));
