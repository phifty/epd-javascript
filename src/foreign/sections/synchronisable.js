
(function ($, $$, $$$, $$$$) {
  "use strict";

  $$$$.ids = function (foreignProfile) {
    return $.Sections.Synchronisable.ids(foreignProfile);
  };

  $$$$.exists = function (foreignProfile, id) {
    return $.Sections.Synchronisable.exists(foreignProfile, id);
  };

  $$$$.byId = function (foreignProfile, id) {
    return $.Sections.Synchronisable.byId(foreignProfile, id);
  };

  $$$$.memberIds = function (foreignProfile, id) {
    var hangOut = $$$$.byId(foreignProfile, id);
    return hangOut ? hangOut.members : [ ];
  };

  $$$$.isDelegated = function (foreignProfile, id) {
    return $.Sections.Synchronisable.isDelegated(foreignProfile, id);
  };

  $$$$.offered = function (profiles, profile) {
    var contactIds = $.Contacts.ids(profile)
      , result = { };

    $.Iterator.each(contactIds, function (_, contactId) {
      var foreignProfile = profiles[ contactId ];
      if (foreignProfile) {
        var hangOutIds = $$$$.ids(foreignProfile);
        $.Iterator.each(hangOutIds, function (_, hangOutId) {
          if (!$.Sections.Synchronisable.byId(profile, hangOutId)) {
            var hangOut = $$$$.byId(foreignProfile, hangOutId);
            result[hangOutId] = result[hangOutId] || { title: hangOut.title, contactId: contactId };
          }
        });
      }
    });

    return result;
  };

  $$$$.differences = function (profiles, profile, id) {
    var memberIds = $.Sections.Synchronisable.memberIds(profile, id)
      , moduleIds = $.Modules.ids(profile, id)
      , notParticipating = { }
      , addMembers = { }, removeMembers = { }
      , addModules = { }, removeModules = { }
      , differences = [ ]

      , pushMember = function (container, keys, memberId) {
          $.Iterator.each(keys, function (_, key) {
            container[key] = container[key] || [ ];
            container[key].push(memberId);
          });
        }

      , pushDifferences = function (container, type) {
          $.Iterator.each(container, function (key, memberIds) {
            differences.push({ type: type, id: key, by: memberIds });
          });
        };

    $.Iterator.each(memberIds, function (_, memberId) {
      var foreignProfile = profiles[memberId];
      if (memberId !== profile.id && foreignProfile && !$$$$.isDelegated(foreignProfile, id)) {
        if ($$$$.exists(foreignProfile, id)) {
          var foreignMemberIds = $$$$.memberIds(foreignProfile, id)
            , addMemberIds = $.Iterator.without(foreignMemberIds, memberIds)
            , removeMemberIds = $.Iterator.without(memberIds, foreignMemberIds)

            , foreignModuleIds = $$.Modules.ids(foreignProfile, id)
            , addModuleIds = $.Iterator.without(foreignModuleIds, moduleIds)
            , removeModuleIds = $.Iterator.without(moduleIds, foreignModuleIds);

          $.Iterator.remove(addMemberIds, profile.id);
          $.Iterator.remove(removeMemberIds, foreignProfile.id);

          pushMember(addMembers, addMemberIds, memberId);
          pushMember(removeMembers, removeMemberIds, memberId);
          pushMember(addModules, addModuleIds, memberId);
          pushMember(removeModules, removeModuleIds, memberId);
        } else {
          pushMember(notParticipating, [ memberId ], profile.id);
        }
      }
    });

    pushDifferences(notParticipating, "not_participating");
    pushDifferences(addMembers, "add_member");
    pushDifferences(removeMembers, "remove_member");
    pushDifferences(addModules, "add_module");
    pushDifferences(removeModules, "remove_module");

    return differences;
  };

}(epdRoot,
  epdRoot.Foreign = epdRoot.Foreign || { },
  epdRoot.Foreign.Sections = epdRoot.Foreign.Sections || { },
  epdRoot.Foreign.Sections.Synchronisable = epdRoot.Foreign.Sections.Synchronisable || { }));
