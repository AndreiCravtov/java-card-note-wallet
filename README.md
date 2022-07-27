# Java Card Bitcoin Note pseudo-wallet

## Learning summary

While learning to work with *Java Card* technologies — written in a subset of the *Java* programming language, I have developed a *Bitcoin* pseudo-wallet which is designed to turn a *Java Card* into a *Bitcoin* banknote, by providing features like transaction signing and secure private key storage. So far, it is a prototype applet.

* *Java* programming language: when developing this project, I had to learn a precise subset of *Java*, and how to make effective use of it. With many restrictions and things like strings, integers missing, I had to learn coding techniques which significantly differ from those used in a *Java* program.
	- One way they differ is the absence of object-oriented design. Every new class entails the final applet getting bigger, and complex OOP patterns with interfaces, inheritance, polymorphism would require a lot of classes and objects in order to work. Hence, because of the hardware limitations, I favoured procedural programming approach due to its reduced overhead.
	- Another way they differ is how much more linked *Java Card* programming is to the hardware than regular *Java*. I had to take into account the types of memory that each line of code is using; the faster and more scarce *RAM* versus the slower and more plentiful *EEPROM* — both types of memory being very small. I had to be mindful of which part of the CPU was executing instructions; lines of code calling on hardware implementations are faster to execute than software implementations.

* *Java Card* technologies: although this technology is ubiquitous, there is a lot of secrecy within the industry.  A lot of NDAs and not a lot of learning resources online when compared to things like *React JS* for example. As a result, I was forced to learn how to learn. I began to read the official user guides and API documentations, examined other example code online, and in some instances used trial and error. From this experience, I've learned a lot about the *Java Card* ecosystem, how to read documentations and specifications, and yet I have more to learn.

* Blockchain: this project is focused around putting digital money into smartcards. Of course I had to learn how blockchain technology worked in order to understand how to use it in a software project. I learned about the *Nakamoto consensus*, and how transactions are facilitated on a blockchain network. Without this knowledge, I wouldn't know what it would take to create a crypto wallet, let alone on a platform like *Java Card*.

* *Bitcoin* protocol: for this project, I needed specific knowledge of the *Bitcoin* protocol. General blockchain knowledge was useful to be able to navigate things, but without *Bitcoin*-specific details, this project couldn't happen. I had to learn about various encoding standards. For the signatures, the *DER* format; for the address, *Base58*; how points on an *Elliptic Curve* are encoded (compressed and uncompressed), and so on. I also had to learn the various algorithm standards when it came to *Bitcoin*. For example, how to derive the *P2PKH* address, the hashing algorithm for *Bitcoin* being a *double-SHA256*, how to construct *P2PKH* transactions and the basics of *Bitcoin* script.
 
 * Security: writing an Applet of this nature for the *Java Card* platform meant I had to make considerations for security. I had to use technologies such as *public key cryptography* and more specifically the *ECDSA* algorithm, to prove that the card which is running the applet has possession of the *private key* without revealing it. This makes the card both functional and secure from attacks which are trying to extract the *private key*.

* Cryptography: in order to understand the both security and blockchain technologies on a deeper level (a level required for this type of project) I needed to learn about cryptographic primitives. I learned some of the math which is needed to construct an *Elliptic Curve Cryptography* system; such as elliptic curve groups over prime finite fields, how that creates the conditions necessary for *ECDLP* to be a secure and practical cryptographic primitive, and how this theory  applies to the various algorithms such as *ECDSA* and *ECDH*.

## How to operate this project

### How to run the project

1. Download the `.cap` file from [here](https://github.com/AndreiCravtov/java-card-note-wallet/releases/tag/Applet).
2. Make sure you have the appropriate smart card software installed on you system, such as [*pcscd*](https://linux.die.net/man/8/pcscd) on Linux.
3. Use [*GlobalPlatformPro*](https://github.com/martinpaljak/GlobalPlatformPro) to communicate with the card.
4. Install the `.cap` file on an EC enabled, 3.0.5 JavaCard.
5. Select the applet with the AID of `010203040506`.
6. Optionally, use the CLI client provided which is written in Python for easier use of the card. To do so, run `python3 main.py`, which can be found within the [*client*](https://github.com/AndreiCravtov/java-card-note-wallet/tree/main/client) folder.

### Application use

The applet works by receiving APDU commands. Those can be sent using [*GlobalPlatformPro*](https://github.com/martinpaljak/GlobalPlatformPro). Here is the instruction set for this applet:
* `B0 00 00 00 41` fetches uncompressed public key.
* `B0 00 01 00 21` fetches compressed public key.
* `B0 01 00 00 19` fetches P2PKH address bytes.
* `B0 02 00 00 20 [NONCE] 48` returns the *ECDSA signature* for the supplied random 32-byte `NONCE`.
* `B0 03 00 00 [A] [B] 48` returns the *ECDSA signature* for the supplied transaction template.
	- `A`: Number of bytes of `B` in hexadecimal.
	- `B`: The transaction template.
* `B0 04 00 00 01` returns the security status of the card.
* `B0 05 00 00 00` resets the card wallet.

## Viewing and  modifying  the project

The [applet repository](https://github.com/AndreiCravtov/java-card-note-wallet-private) repository is an Intellij IDEA project. It can be opened and edited by cloning this repo and opening the repo folder in Intellij IDEA like any other project. From there, the source code can be viewed and modified. The project can be built using [*ant-javacard*](https://github.com/martinpaljak/ant-javacard).
