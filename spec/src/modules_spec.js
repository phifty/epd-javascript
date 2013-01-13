
describe("Modules", function () {

  var namespace = epdRoot.Modules
    , profile;

  beforeEach(function () {
    profile = epdRoot.Object.clone(fixtures.profile());
  });

  describe("#ids", function () {

    it("should return an array with all module ids", function () {
      var ids = namespace.ids(profile, "open");
      expect(ids).toEqual([ "build_in:com.anyaku.Basic" ]);
    });

    it("should return an empty array if section id could not be found", function () {
      var ids = namespace.ids(profile, "missing");
      expect(ids).toEqual([ ]);
    });

  });

  describe("#exists", function () {

    it("should return true if the given module is existing", function () {
      var result = namespace.exists(profile, "open", "build_in:com.anyaku.Basic");
      expect(result).toBeTruthy();
    });

    it("should return false if the given module is missing", function () {
      var result = namespace.exists(profile, "open", "missing");
      expect(result).toBeFalsy();
    });

    it("should return false if the given module is in a locked section", function () {
      var result = namespace.exists(fixtures.lockedProfile(), "closed", "build_in:com.anyaku.Basic");
      expect(result).toBeFalsy();
    });

  });

  describe("#byId", function () {

    it("should return the module by the given id", function () {
      var module = namespace.byId(profile, "open", "build_in:com.anyaku.Basic");
      expect(module.content).toEqual({ });
    });

    it("should throw an error if the given module id is undefined", function () {
      expect(function () {
        namespace.byId(profile, "open", undefined);
      }).toThrow("the module undefined does not exists");
    });

    it("should throw an error if the given module is in a locked section", function () {
      expect(function () {
        namespace.byId(fixtures.lockedProfile(), "closed", "build_in:com.anyaku.Basic");
      }).toThrow("the module build_in:com.anyaku.Basic does not exists");
    });

  });

  describe("#ensureOnly", function () {

    it("should remove all modules that are not in the given ids", function () {
      profile = namespace.ensureOnly(profile, "open", [ ]);
      expect(namespace.ids(profile, "open")).toEqual([ ]);
    });

    it("should leave the modules untouched if given ids reflects exactly the sections current state", function () {
      profile = namespace.ensureOnly(profile, "open", [ "build_in:com.anyaku.Basic" ]);
      expect(namespace.ids(profile, "open")).toEqual([ "build_in:com.anyaku.Basic" ]);
    });

    it("should add modules if the given id is not already added", function () {
      profile = namespace.ensureOnly(profile, "test", [ "build_in:com.anyaku.Basic" ]);
      expect(namespace.ids(profile, "test")).toEqual([ "build_in:com.anyaku.Basic" ]);
    });

  });

  describe("#ensureAdded", function () {

    it("should ensure that the given modules are added to the given section", function () {
      var id = namespace.ensureAdded(profile, "test", [ "build_in:com.anyaku.Basic" ]);
      expect(namespace.ids(profile, "test")).toContain(id);
    });

  });

  describe("#ensureRemoved", function () {

    it("should ensure that the given modules are removed from the given section", function () {
      profile = namespace.ensureRemoved(profile, "open", [ "build_in:com.anyaku.Basic" ]);
      expect(namespace.ids(profile, "open")).not.toContain("build_in:com.anyaku.Basic");
    });

  });

  describe("#add", function () {

    it("should add the given module to the given section and return the module id", function () {
      var id = namespace.add(profile, "test", "build_in:com.anyaku.Basic");
      expect(namespace.ids(profile, "test")).toContain(id);
    });

    it("should throw an error if the given module has been added before", function () {
      expect(function () {
        namespace.add(profile, "open", "build_in:com.anyaku.Basic");
      }).toThrow("the module build_in:com.anyaku.Basic is already existing");
    });

  });

  describe("#remove", function () {

    it("should return a profile where the given module is removed from the given section", function () {
      profile = namespace.remove(profile, "open", "build_in:com.anyaku.Basic");
      expect(namespace.ids(profile, "open")).not.toContain("build_in:com.anyaku.Basic");
    });

  });

  describe("#contents", function () {

    it("should return all contents for the given module sorted by sections", function () {
      var contents = namespace.contents(profile, "build_in:com.anyaku.Basic");
      expect(contents).toEqual({ open: { } });
    });

  });

});
