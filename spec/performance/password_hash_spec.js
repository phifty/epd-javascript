
describe("Performance", function () {

  describe("Password hash", function () {

    var password = "test"
      , keySize = 160/32;

    it("should hash the password in an appropriate time", function () {
      var durations = benchmark.measureEach([ 1, 10, 100, 1000, 10000 ], function (iterations) {
        epdRoot.Crypt.Password.hash(password, { iterations: iterations, keySize: keySize })
      });
    });

  });

});
