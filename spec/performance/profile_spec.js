
describe("Performance", function () {

  describe("Profile", function () {

    var profile
      , keyPair
      , profileSize = function () {
          var lockedProfile = epdRoot.Locker.lock(profile, fixtures.password())
            , lockedProfileString = JSON.stringify(lockedProfile);

          return lockedProfileString.length;
        }
      , difference = function (a, b) { return b - a; };

    beforeEach(function () {
      if (!profile) {
        profile = epdRoot.Object.clone(fixtures.profile());
        keyPair = epdRoot.Crypt.Asymmetric.generateKeyPair();
      }
    });

    it("should not grow to much if new contacts are added", function () {
      var sizes = [ ];

      sizes.push(profileSize());
      for (var index = 0; index < 10; index++) {
        var contactProfileId = epdRoot.Crypt.Object.generateId();
        epdRoot.Contacts.add(profile, contactProfileId, keyPair.publicKey);
        sizes.push(profileSize());
      }

      var accelerations = epdRoot.Iterator.pair(epdRoot.Iterator.pair(sizes, difference), difference)
        , average = epdRoot.Iterator.reduce(accelerations, 0, function (result, acceleration) {
            return result + acceleration;
          }) / accelerations.length;

      expect(average).toBeCloseTo(0, 0);
    });

    it("should not grow the profile when locked and unlocked multiple times without change", function () {
      var sizes = [ ];

      // old profiles have this obsolete sections key for the profile's owner contact
      profile.contacts[ profile.id ].sections = [ "test" ];

      sizes.push(profileSize());
      for (var index = 0; index < 10; index++) {
        profile = epdRoot.Locker.unlock(epdRoot.Locker.lock(profile, fixtures.password()), fixtures.password());
        sizes.push(profileSize());
      }

      var grows = epdRoot.Iterator.pair(sizes, difference)
        , average = epdRoot.Iterator.reduce(grows, 0, function (result, grow) {
            return result + grow;
          }) / grows.length;

      expect(average).toBeCloseTo(0, 0);
    });

  });

});
