
# Encrypted Profile Documents

The encrypted profile document (EPD) format acts as an encryption container of information that the author wants to
keep private or share with a defined set of other EPD authors. It enables the author to clearly separate private and
shared data and keep control about what information can be accessed by others. This is achieved by a combination of
symmetric and asymmetric encryption methods, which are chained together in the process of encrypting and decrypting
(locking and unlocking) an EPD. Each EPD contains, beside the payload data and some encryption overhead, also
information about the author and his signature, which enables a random reader to verify the authenticity of the EPD,
even if the content cannot be unlocked.

This library can handle EPDs and is implemented in pure Javascript. It's compatible with the latest versions of Firefox
and Chrome.

## Build the library and run the specs

Ruby is needed to build the library. Simple enter the following commands.

    git clone https://github.com/phifty/epd-javascript.git
    cd epd-javascript
    bundle install
    rake assets:build

The generated library can be found under `artefacts/epd.js`.

A simple server which provides a runner for the jasmine spec suit can be started with...

    rake jasmine

Afterwards, point your browser to `http://localhost:8888`.

## Usage

After you include the library, the global variable `epdRoot` contains the root namespace of the library. To generate a
fresh EPD type...

    var epd = epdRoot.Generator.generate();

A foreign EPD can be added to the contacts.

    epdRoot.Contacts.add(epd, foreignEpd.id, foreignEpd.publicKey);

In order the shared information, a section can be created.

    var sectionId = epdRoot.Sections.add(epd, "Friends")
      , section = epdRoot.Sections.byId(epd, sectionId);

    section.message = "Hello to all my friends!";

Contacts can be added as section members to make the content accessible to them.

    epdRoot.Sections.addMember(epd, foreignEpd.id, sectionId);

The now filled EPD, can be locked by using a password.

    var passwordHash = epdRoot.Crypt.Password.hash("secret")
      , lockedEpd = epdRoot.Locker.lock(epd, passwordHash);

Unlocking using a password is similar.

    epd = epdRoot.Locker.unlock(lockedEpd, passwordHash);

Each locked EPD contains a signature that validates the authenticity of the EPD. A check can be performed by...

    var isVerified = epdRoot.Signer.verify(foreignEpd, foreignEpd.signature, foreignEpd.publicKey);

If you receive a foreign locked EPD, you can use the private key in your own unlocked EPD to perform a partial unlock.

    var unlockedForeignEpd = epdRoot.Foreign.Locker.unlock(foreignEpd, epd);
      , foreignSectionIds = epdRoot.Sections.ids(foreignEpd)
      , foreignSection = epdRoot.Sections.byId(foreignEpd, foreignSectionIds[0]);

    foreignSection.message // => "...Message form the other EPD's author..."

## Contribution

Any contribution is very welcome. If code is contributed, please make sure that tests are included.

## License

[![Creative Commons License](http://i.creativecommons.org/l/by-nc-sa/3.0/80x15.png)](http://creativecommons.org/licenses/by-nc-sa/3.0/)
This work is licensed under a
[Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License](http://creativecommons.org/licenses/by-nc-sa/3.0/).
