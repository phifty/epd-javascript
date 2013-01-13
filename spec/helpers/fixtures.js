
var fixtures = {

  data: { },

  _getOrGenerate: function (key, generator) {
    if (!this.data[key]) {
      this.data[key] = generator.apply(this);
    }
    return this.data[key];
  },

  rsaKey: function () {
    return this._getOrGenerate("rsaKey", function () {
      return { type: "rsaKey", modulus: [ 1, 2, 3 ], exponent: [ 4, 5, 6 ] };
    });
  },

  encodedRsaKey: function () {
    return this._getOrGenerate("encodedRsaKey", function () {
      return epdRoot.Crypt.Coder.encode(this.rsaKey());
    });
  },

  keyPair: function () {
    return this._getOrGenerate("keyPair", function () {
      return epdRoot.Crypt.Asymmetric.generateKeyPair();
    });
  },

  key: function () {
    return this._getOrGenerate("key", function () {
      return epdRoot.Crypt.Symmetric.generateKey();
    });
  },

  invalidKey: function () {
    return this._getOrGenerate("invalidKey", function () {
      return epdRoot.Crypt.Symmetric.generateKey();
    });
  },

  password: function () {
    return this._getOrGenerate("password", function () {
      return epdRoot.Crypt.Password.hash("test password");
    });
  },

  invalidPassword: function () {
    return this._getOrGenerate("invalidPassword", function () {
      return epdRoot.Crypt.Password.hash("invalid password");
    });
  },

  message: function () {
    return this._getOrGenerate("message", function () {
      return "test";
    });
  },

  largeMessage: function () {
    return this._getOrGenerate("largeMessage", function () {
      var message = "test";
      for (var index = 0; index < 5; index++) {
        message = message + message;
      }
      return message;
    });
  },

  encryptedMessage: function () {
    return this._getOrGenerate("encryptedMessage", function () {
      return epdRoot.Crypt.Symmetric.encrypt(this.message(), this.key());
    });
  },

  messageSignature: function () {
    return this._getOrGenerate("messageSignature", function () {
      return epdRoot.Crypt.Asymmetric.sign(this.message(), this.keyPair().publicKey, this.keyPair().privateKey);
    });
  },

  object: function () {
    return this._getOrGenerate("object", function () {
      return { test: "value" };
    });
  },

  largeObject: function () {
    return this._getOrGenerate("largeObject", function () {
      return { test: this.largeMessage() };
    });
  },

  encryptedObject: function () {
    return this._getOrGenerate("encryptedObject", function () {
      return epdRoot.Crypt.Symmetric.Object.encrypt(this.object(), this.key());
    });
  },

  signedObject: function () {
    return this._getOrGenerate("signedObject", function () {
      return epdRoot.Crypt.Asymmetric.Object.sign(epdRoot.Object.clone(this.object()), this.keyPair().publicKey, this.keyPair().privateKey);
    });
  },

  profile: function () {
    return this._getOrGenerate("profile", function () {
      var profile = epdRoot.Generator.generate()
        , sectionId = epdRoot.Sections.add(profile, "Test", "test");
      profile = epdRoot.Contacts.add(profile, this.anotherProfile().id, this.anotherProfile().publicKey);
      profile = epdRoot.Sections.addMember(profile, this.anotherProfile().id, sectionId);
      return profile;
    });
  },

  minimalProfile: function () {
    return this._getOrGenerate("minimalProfile", function () {
      return {
        id: this.profile().id,
        publicKey: this.profile().publicKey
      };
    });
  },

  section: function () {
    return this._getOrGenerate("section", function () {
      return epdRoot.Sections.byId(this.profile(), "test");
    });
  },

  openSection: function () {
    return this._getOrGenerate("openSection", function () {
      var section = { modules: { } };
      section.modules["build_in:com.anyaku.Basic"] = this.module();
      return section;
    });
  },

  module: function () {
    return this._getOrGenerate("module", function () {
      return epdRoot.Modules.byId(this.profile(), "open", "build_in:com.anyaku.Basic");
    });
  },

  anotherProfile: function () {
    return this._getOrGenerate("anotherProfile", function () {
      return epdRoot.Generator.generate();
    });
  },

  lockedProfile: function () {
    return this._getOrGenerate("lockedProfile", function () {
      return epdRoot.Locker.lock(this.profile(), this.password());
    });
  },

  signedProfile: function () {
    return this._getOrGenerate("signedProfile", function () {
      return epdRoot.Signer.sign(epdRoot.Object.clone(this.lockedProfile()), this.profile().publicKey, this.profile().privateKey);
    });
  },

  profileUnlockedByStranger: function () {
    return this._getOrGenerate("profileUnlockedByStranger", function () {
      return epdRoot.Foreign.Locker.unlock(this.lockedProfile(), this.anotherProfile());
    });
  },

  testHangOutId: function () {
    return this._getOrGenerate("testHangOutId", function () {
      var hangOutId = epdRoot.Sections.HangOuts.add(this.profile(), "Test hang out", "test_hang_out");

      epdRoot.Sections.HangOuts.addMember(this.profile(), this.anotherProfile().id, hangOutId);
      epdRoot.Modules.add(this.profile(), hangOutId, "build_in:com.anyaku.Forum");

      epdRoot.Contacts.add(this.anotherProfile(), this.profile().id, this.profile().publicKey);
      epdRoot.Sections.HangOuts.add(this.anotherProfile(), "Test hang out", hangOutId);
      epdRoot.Sections.HangOuts.addMember(this.anotherProfile(), this.profile().id, hangOutId);
      epdRoot.Modules.add(this.anotherProfile(), hangOutId, "build_in:com.anyaku.Forum");

      return hangOutId;
    });
  }

};
