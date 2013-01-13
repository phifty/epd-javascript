
(function ($, $$, $$$) {
  "use strict";

  var _forContacts = function (contactIds, profiles, handler) {
        $.Iterator.each(contactIds, function (index, contactId) {
          var contactProfile = profiles[contactId];
          if (contactProfile) {
            handler(contactId, contactProfile);
          }
        });
      };

  $$$.ids = function (foreignProfile, sectionId) {
    return $.Modules.ids(foreignProfile, sectionId);
  };

  $$$.contents = function (profile, id, profiles) {
    var contents = { };

    _forContacts($.Contacts.ids(profile), profiles, function (contactId, contactProfile) {
      var sectionIds = $.Sections.openIds.concat($.Sections.ids(contactProfile));
      $.Iterator.each(sectionIds, function (index, sectionId) {
        if ($.Modules.exists(contactProfile, sectionId, id)) {
          var module = $.Modules.byId(contactProfile, sectionId, id);
          contents[contactId] = contents[contactId] || { };
          contents[contactId][sectionId] = module.content;
        }
      });
    });

    return contents;
  };

  $$$.contentsForSection = function (profile, sectionId, id, profiles) {
    var contents = { };

    _forContacts($.Contacts.idsBySectionId(profile, sectionId), profiles, function (contactId, contactProfile) {
      if ($.Modules.exists(contactProfile, sectionId, id)) {
        var module = $.Modules.byId(contactProfile, sectionId, id);
        contents[contactId] = module.content;
      }
    });

    return contents;
  };

}(epdRoot,
  epdRoot.Foreign = epdRoot.Foreign || { },
  epdRoot.Foreign.Modules = epdRoot.Foreign.Modules || { }));
