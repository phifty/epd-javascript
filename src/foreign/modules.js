
(function ($, $$, $$$) {
  "use strict";

  var _forContacts = function (contactIds, profileGetFunction, handler) {
        $.Iterator.each(contactIds, function (index, contactId) {
          var contactProfile = profileGetFunction(contactId);
          if (contactProfile) {
            handler(contactId, contactProfile);
          }
        });
      };

  $$$.ids = function (foreignProfile, sectionId) {
    return $.Modules.ids(foreignProfile, sectionId);
  };

  $$$.contents = function (profile, id, profileGetFunction) {
    var contents = { };

    _forContacts($.Contacts.ids(profile), profileGetFunction, function (contactId, contactProfile) {
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

  $$$.contentsForSection = function (profile, sectionId, id, profileGetFunction) {
    var contents = { };

    _forContacts($.Contacts.idsBySectionId(profile, sectionId), profileGetFunction, function (contactId, contactProfile) {
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
