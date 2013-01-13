
describe("Crypt.Password", function () {

  var namespace = epdRoot.Crypt.Password;

  describe("#hash", function () {

    var password;

    beforeEach(function () {
      if (!password) {
        password = namespace.hash("test");
      }
    });

    it("should return the hashed version of the given password", function () {
      expect(password.hash).toBeOfType("aesKey");
    });

    it("should return the generated salt", function () {
      expect(password.salt).toBeOfType("salt");
    });

    it("should return the same hashed version if password and all parameters are the same", function () {
      var result = namespace.hash("test", { salt: password.salt, keySize: password.keySize, iterations: password.iterations });

      expect(result).toEqual(password);
    });

    it("should throw an error is no password is given", function () {
      expect(function () {
        namespace.hash(undefined);
      }).toThrow("no password given");
    });

  });

  describe("#benchmark", function () {

    it("should return the duration in ms for the given number of iterations", function () {
      var duration = namespace.benchmark(100);
      expect(duration).toBeGreaterThan(1);
    });

  });

});
