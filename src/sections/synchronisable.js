
(function ($, $$, $$$) {
  "use strict";

  $$$.ids = function (profile) {
    return $.Collection.select($$.ids(profile), function (index, id) {
      return $$$.isSynchronisable(profile, id);
    });
  };

  $$$.exists = function (profile, id) {
    return $$.exists(profile, id);
  };

  $$$.byId = function (profile, id) {
    return $$.byId(profile, id);
  };

  $$$.isSynchronisable = function (profile, id) {
    var section = $$$.byId(profile, id);
    return section && !!section.members;
  };

  $$$.add = function (profile, title, id) {
    var sectionId = $$.add(profile, title, id)
      , section = $$.byId(profile, sectionId);

    section.members = [ ];

    return sectionId;
  };

  $$$.remove = function (profile, id) {
    return $$.remove(profile, id);
  };

  $$$.memberIds = function (profile, id) {
    return $.Collection.select($.Contacts.ids(profile), function (_, contactId) {
      return $$$.isMember(profile, contactId, id);
    });
  };

  $$$.addMember = function (profile, contactId, id) {
    if ($$$.isMember(profile, contactId, id)) {
      return profile;
    }

    var section = $$$.byId(profile, id);
    section.members.push(contactId);
    return $$.addMember(profile, contactId, id);
  };

  $$$.removeMember = function (profile, contactId, id) {
    if (!$$$.isMember(profile, contactId, id)) {
      return profile;
    }

    var section = $$$.byId(profile, id);
    $.Collection.remove(section.members, contactId);
    return $$.removeMember(profile, contactId, id);
  };

  $$$.isMember = function (profile, contactId, id) {
    var section = $$$.byId(profile, id);
    return $$.isMember(profile, contactId, id) && $.Collection.include(section.members, contactId);
  };

  // high level

  $$$.addMembers = function (profile, contactIds, id) {
    return $$.addMembers(profile, contactIds, id, $$$);
  };

  $$$.removeMembers = function (profile, contactIds, id) {
    return $$.removeMembers(profile, contactIds, id, $$$);
  };

  $$$.ensureOnlyMembers = function (profile, contactIds, id) {
    return $$.ensureOnlyMembers(profile, contactIds, id, $$$);
  };

  $$$.delegateTo = function (profile, contactId, id) {
    var hangOut = $$$.byId(profile, id);
    hangOut.administrationDelegatedTo = contactId;

    return profile;
  };

  $$$.removeDelegation = function (profile, id) {
    var hangOut = $$$.byId(profile, id);
    delete(hangOut.administrationDelegatedTo);
    return profile;
  };

  $$$.delegatedTo = function (profile, id) {
    var hangOut = $$$.byId(profile, id);
    return hangOut.administrationDelegatedTo;
  };

  $$$.isDelegated = function (profile, id) {
    var hangOut = $$$.byId(profile, id);
    return !!hangOut && !!hangOut.administrationDelegatedTo;
  };

  $$$.followAllDelegations = function (profile, profileGetFunction) {
    var result = { };

    $.Iterator.each($$$.ids(profile), function (_, id) {
      result[ id ] = $$$.followDelegation(profile, id, profileGetFunction);
    });

    return result;
  };

  $$$.followDelegation = function (profile, id, profileGetFunction) {
    var result = { }

      , findDelegationTargetProfile = function () {
          var result = profile;

          while (result && $$$.isDelegated(result, id)) {
            var nextProfileId = $$$.delegatedTo(result, id)
              , nextProfile = profileGetFunction(nextProfileId);

            if (nextProfileId === profile.id) {
              return profile;
            } else {
              if (nextProfile) {
                result = nextProfile;
              } else {
                return result;
              }
            }
          }

          return result;
        }

      , removeDelegation = function () {
          $$$.removeDelegation(profile, id);
        };

    if ($$$.isDelegated(profile, id)) {
      var targetProfile = findDelegationTargetProfile();
      if (targetProfile && targetProfile.id !== profile.id) {
        if (targetProfile.id !== $$$.delegatedTo(profile, id)) {
          $$$.delegateTo(profile, targetProfile.id, id);
        }

        if ($.Collection.include($.Foreign.Sections.Synchronisable.ids(targetProfile), id)) {
          var memberIds = [ profile.id ].concat($$$.memberIds(profile, id))
            , targetMemberIds = [ targetProfile.id ].concat($.Foreign.Sections.Synchronisable.memberIds(targetProfile, id))
            , addMemberIds = $.Collection.without(targetMemberIds, memberIds)
            , removeMemberIds = $.Collection.without(memberIds, targetMemberIds)

            , moduleIds = $.Modules.ids(profile, id)
            , targetModuleIds = $.Foreign.Modules.ids(targetProfile, id)
            , addModuleIds = $.Collection.without(targetModuleIds, moduleIds)
            , removeModuleIds = $.Collection.without(moduleIds, targetModuleIds);

          if (addMemberIds.length > 0) { result.addMembers = addMemberIds; }
          if (removeMemberIds.length > 0) { result.removeMembers = removeMemberIds; }
          if (addModuleIds.length > 0) { result.addModules = addModuleIds; }
          if (removeModuleIds.length > 0) { result.removeModules = removeModuleIds; }
        } else {
          removeDelegation();
        }
      } else {
        removeDelegation();
      }
    }

    return result;
  };

}(epdRoot,
  epdRoot.Sections = epdRoot.Sections || { },
  epdRoot.Sections.Synchronisable = epdRoot.Sections.Synchronisable || { }));
