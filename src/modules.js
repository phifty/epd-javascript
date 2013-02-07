
(function ($, $$) {
  "use strict";

  $$.ids = function (profile, sectionId) {
    var section = $.Sections.byId(profile, sectionId);
    return section ? $.Object.keys(section.modules) : [ ];
  };

  $$.exists = function (profile, sectionId, id) {
    var section = $.Sections.byId(profile, sectionId);
    return section && !$.Crypt.Coder.isEncoded(section) ? !!section.modules[id] : false;
  };

  $$.byId = function (profile, sectionId, id) {
    if (!$$.exists(profile, sectionId, id)) {
      throw(new Error("the module " + id + " does not exists"));
    }
    return $.Sections.byId(profile, sectionId).modules[id];
  };

  $$.ensureOnly = function (profile, sectionId, ids) {
    // remove modules, that are not on the list
    $.Iterator.each($$.ids(profile, sectionId), function (index, id) {
      if (!$.Collection.include(ids, id)) {
        profile = $$.remove(profile, sectionId, id);
      }
    });

    // add modules, that are not added yet
    $.Iterator.each(ids, function (index, id) {
      if (!$$.exists(profile, sectionId, id)) {
        $$.add(profile, sectionId, id);
      }
    });

    return profile;
  };

  $$.ensureAdded = function (profile, sectionId, ids) {
    var moduleIds = $$.ids(profile, sectionId);
    $.Iterator.each(ids, function (_, id) {
      if (!$.Collection.include(moduleIds, id)) {
        profile = $$.add(profile, sectionId, id);
      }
    });
    return profile;
  };

  $$.ensureRemoved = function (profile, sectionId, ids) {
    var moduleIds = $$.ids(profile, sectionId);
    $.Iterator.each(ids, function (_, id) {
      if ($.Collection.include(moduleIds, id)) {
        profile = $$.remove(profile, sectionId, id);
      }
    });
    return profile;
  };

  $$.add = function (profile, sectionId, id) {
    var section = $.Sections.byId(profile, sectionId);

    if ($$.exists(profile, sectionId, id)) {
      throw(new Error("the module " + id + " is already existing"));
    }

    section.modules[id] = {
      content: { }
    };

    return id;
  };

  $$.remove = function (profile, sectionId, id) {
    var section = $.Sections.byId(profile, sectionId);

    delete(section.modules[id]);

    return profile;
  };

  $$.contents = function (profile, id) {
    var contents = { };

    $.Iterator.each($.Sections.fixedIds.concat($.Sections.ids(profile)), function (_, sectionId) {
      if ($$.exists(profile, sectionId, id)) {
        var module = $$.byId(profile, sectionId, id);
        contents[sectionId] = module.content;
      }
    });

    return contents;
  };

}(epdRoot,
  epdRoot.Modules = epdRoot.Modules || { }));
