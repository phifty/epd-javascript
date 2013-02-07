
(function ($, $$) {
  "use strict";

  $$.openIds = [ "open" ];
  $$.closedIds = [ "closed" ];
  $$.fixedIds = [ "open", "closed" ];

  $$.ids = function (profile) {
    var results = [ ];
    $.Iterator.each(profile.sections, function (id) {
      if (!$.Collection.include($$.fixedIds, id)) {
        results.push(id);
      }
    });
    return results;
  };

  $$.exists = function (profile, id) {
    return !!profile.sections[id];
  };

  $$.byId = function (profile, id) {
    return profile.sections[id];
  };

  $$.add = function (profile, title, id) {
    id = id || $.Crypt.Object.generateId(4);

    if ($$.exists(profile, id)) {
      throw(new Error("the section " + id + " is already existing"));
    }

    profile.sections[id] = { modules: { } };
    if (title) {
      profile.sections[id].title = title;
    }

    $$.addMember(profile, profile.id, id);

    return id;
  };

  $$.remove = function (profile, id) {
    profile = $$.removeAllMembers(profile, id);
    profile = $$.removeMember(profile, profile.id, id);
    delete(profile.sections[id]);
    return profile;
  };

  $$.memberIds = function (profile, id) {
    return $.Collection.select($.Contacts.ids(profile), function (_, contactId) {
      return $$.isMember(profile, contactId, id);
    });
  };

  $$.addMember = function (profile, contactId, id) {
    if ($$.isMember(profile, contactId, id)) {
      return profile;
    }

    var container = profile.contacts[contactId];
    if (profile.id !== contactId) {
      container.sections.push(id);
    }
    container.keys[id] = $$.findKey(profile.contacts, id) || $.Crypt.Symmetric.generateKey();

    return profile;
  };

  $$.removeMember = function (profile, contactId, id) {
    if (!$$.isMember(profile, contactId, id)) {
      return profile;
    }

    var container = profile.contacts[contactId];
    $.Collection.remove(container.sections, id);
    delete(container.keys[id]);

    return profile;
  };

  $$.isMember = function (profile, contactId, id) {
    return ($.Collection.include($$.openIds, id)) ||
           (!!profile.contacts[contactId] &&
             !!profile.contacts[contactId].keys &&
             !!profile.contacts[contactId].keys[id]);
  };

  $$.findKey = function (contacts, id) {
    var result = $.Collection.detect(contacts, function (_, container) {
      return !!container.keys && !!container.keys[id];
    });
    return result ? result.keys[id] : undefined;
  };

  // high level

  $$.addMembers = function (profile, contactIds, id, base) {
    base = base || $$;
    $.Iterator.each(contactIds, function (_, contactId) {
      base.addMember(profile, contactId, id);
    });
    return profile;
  };

  $$.removeAllMembers = function (profile, id, base) {
    return $$.removeMembers(profile, $$.memberIds(profile, id), id, base);
  };

  $$.removeMembers = function (profile, contactIds, id, base) {
    base = base || $$;
    $.Iterator.each(contactIds, function (_, contactId) {
      base.removeMember(profile, contactId, id);
    });
    return profile;
  };

  $$.ensureOnlyMembers = function (profile, contactIds, id, base) {
    base = base || $$;

    // remove member ids, that are not on the list
    base.removeMembers(profile, $.Collection.without(base.memberIds(profile, id), contactIds), id, base);

    // add member ids, that are not allowed yet
    base.addMembers(profile, contactIds, id, base);

    return profile;
  };

}(epdRoot,
  epdRoot.Sections = epdRoot.Sections || { }));
