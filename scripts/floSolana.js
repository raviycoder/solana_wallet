(function (EXPORTS) {
  //floEthereum v1.0.1a
  /* FLO Ethereum Operators */
  /* Make sure you added Taproot, Keccak, FLO and BTC Libraries before */
  "use strict";
  const floSolana = EXPORTS;

  var bs58 = (function () {
    const ALPHABET =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const BASE = ALPHABET.length;

    // Convert a byte array to a Base58 string
    function encode(buffer) {
      if (buffer.length === 0) return "";

      // Convert byte array to a BigInt
      let intVal = BigInt(0);
      for (let i = 0; i < buffer.length; i++) {
        intVal = intVal * BigInt(256) + BigInt(buffer[i]);
      }

      // Convert BigInt to Base58 string
      let result = "";
      while (intVal > 0) {
        const remainder = intVal % BigInt(BASE);
        intVal = intVal / BigInt(BASE);
        result = ALPHABET[Number(remainder)] + result;
      }

      // Add '1' for each leading 0 byte in the byte array
      for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
        result = ALPHABET[0] + result;
      }

      return result;
    }

    // Convert a Base58 string to a byte array
    function decode(string) {
      if (string.length === 0) return new Uint8Array();

      // Convert Base58 string to BigInt
      let intVal = BigInt(0);
      for (let i = 0; i < string.length; i++) {
        const charIndex = ALPHABET.indexOf(string[i]);
        if (charIndex < 0) {
          throw new Error("Invalid Base58 character");
        }
        intVal = intVal * BigInt(BASE) + BigInt(charIndex);
      }

      // Convert BigInt to byte array
      const byteArray = [];
      while (intVal > 0) {
        byteArray.push(Number(intVal % BigInt(256)));
        intVal = intVal / BigInt(256);
      }

      // Reverse the byte array and add leading zeros
      byteArray.reverse();
      for (let i = 0; i < string.length && string[i] === ALPHABET[0]; i++) {
        byteArray.unshift(0);
      }

      return Uint8Array.from(byteArray);
    }

    return { encode, decode };
  })();

  const solanaSeed2SolanaAddress = (floSolana.solanaSeed2SolanaAddress =
    function (solanaSeed) {
      var k1, k2, k3, k4, k5;

      k2 = Crypto.util.hexToBytes(solanaSeed);
      k3 = Uint8Array.from(k2);
      k4 = solanaWeb3.Keypair.fromSeed(k3);
      k5 = k4.publicKey.toString();
      return k5;
    });

  /*floSolana.solanaSeedUint82wif = function(solanaSeedUint8){
    var k1,k2,k3,k4;
    k1 = solanaWeb3.Keypair.fromSeed(solanaSeedUint8);
    k2 = Array.from(k1.secretKey);
    k3 = k2.slice(0,32);
    k4 = coinjs.privkey2wif(k3);
    return k4;
};*/

  // isFLO = true for FLO wif, omit this for Bitcoin wif
  const solanaSeed2wif = (floSolana.solanaSeed2wif = function (
    solanaSeed,
    isFLO
  ) {
    var p1, p2, k1, k2, k3, k4, k5, temp;
    p1 = Crypto.util.hexToBytes(solanaSeed);
    p2 = Uint8Array.from(p1);
    k1 = solanaWeb3.Keypair.fromSeed(p2);
    k2 = Array.from(k1.secretKey);
    k3 = k2.slice(0, 32);
    k4 = Crypto.util.bytesToHex(k3);
    coinjs.compressed = true;
    temp = coinjs.priv;
    if (isFLO == true) {
      coinjs.priv = 0xa3;
    }
    k5 = coinjs.privkey2wif(k4);
    coinjs.priv = temp;
    return k5;
  });

  const solanaSeed2SolanaSecret = (floSolana.solanaSeed2SolanaSecret =
    function (solanaSeed) {
      var p1, p2, k1, k2, k3, k4, k5, temp;
      p1 = Crypto.util.hexToBytes(solanaSeed);
      p2 = Uint8Array.from(p1);
      k1 = solanaWeb3.Keypair.fromSeed(p2);
      k2 = k1.secretKey;
      k3 = bs58.encode(k2);
      return k3;
    });

  /*floSolana.wif2SolanaSeedUint8 = function(wif){
    var k1,k2,k3;
    k1 = coinjs.wif2privkey(wif);
    k2 = Crypto.util.hexToBytes(k1.privkey);
    k3 = Uint8Array.from(k2);
    return k3;
};*/

  const solanaSeed2UsableInCode = (floSolana.solanaSeed2UsableInCode =
    function (solanaSeed) {
      var k1, k2, k3;
      k2 = Crypto.util.hexToBytes(solanaSeed);
      k3 = Uint8Array.from(k2);
      return k3;
    });

  const wif2SolanaSeed = (floSolana.wif2SolanaSeed = function (wif) {
    var k1;
    k1 = coinjs.wif2privkey(wif);
    return k1.privkey;
  });

  const wif2SolanaAddress = (floSolana.wif2SolanaAddress = function (wif) {
    var k1, k2, k3, k4, k5;
    k1 = coinjs.wif2privkey(wif);
    k2 = Crypto.util.hexToBytes(k1.privkey);
    k3 = Uint8Array.from(k2);
    k4 = solanaWeb3.Keypair.fromSeed(k3);
    k5 = k4.publicKey.toString();
    return k5;
  });

  const wif2SolanaSecret = (floSolana.wif2SolanaSecret = function (wif) {
    var k1, k2;
    k1 = coinjs.wif2privkey(wif);
    k2 = floSolana.solanaSeed2SolanaSecret(k1.privkey);
    return k2;
  });

  const wif2address = (floSolana.wif2address = function (wif, isFLO = false) {
    try {
      // Decode WIF to get the private key
      const privateKeyHex = coinjs.wif2privkey(wif).privkey;
      const privateKeyBytes = Crypto.util.hexToBytes(privateKeyHex);

      // Generate public key from the private key
      const privateKey = new Uint8Array(privateKeyBytes);
      const keyPair = solanaWeb3.Keypair.fromSeed(privateKey);
      const publicKey = keyPair.publicKey.toBuffer();

      // Hash the public key (SHA-256 then RIPEMD-160)
      const sha256Hash = Crypto.SHA256(publicKey);
      const ripemd160Hash = Crypto.RIPEMD160(
        Crypto.util.hexToBytes(sha256Hash)
      );

      // Add network byte (0x00 for Bitcoin, 0x23 for FLO) and compute checksum
      const networkByte = [isFLO ? 0x23 : 0x00];
      const networkAndHash = networkByte.concat(
        Crypto.util.hexToBytes(ripemd160Hash)
      );
      const doubleSHA256 = Crypto.SHA256(Crypto.SHA256(networkAndHash));
      const checksum = doubleSHA256.slice(0, 8);

      // Create the final address
      const addressBytes = networkAndHash.concat(
        Crypto.util.hexToBytes(checksum)
      );
      const address = bs58.encode(addressBytes);

      return address;
    } catch (err) {
      console.error("Error converting WIF to address:", err);
      return null;
    }
  });

  const address2wif = function (address, isFLO = false) {
    try {
      // Decode address to get the public key hash
      const addressBytes = bs58.decode(address);
      const publicKeyHash = addressBytes.slice(1, -4); // Remove network byte and checksum

      // Generate private key from the public key hash (inverse operation)
      const privateKey = solanaWeb3.Keypair.fromSeed(publicKeyHash);
      const privateKeyHex = Crypto.util.bytesToHex(
        Array.from(privateKey.secretKey).slice(0, 32)
      );

      // Convert private key to WIF format
      coinjs.compressed = true;
      const temp = coinjs.priv;
      if (isFLO) {
        coinjs.priv = 0xa3;
      }
      const wif = coinjs.privkey2wif(privateKeyHex);
      coinjs.priv = temp;

      return wif;
    } catch (err) {
      console.error("Error converting address to WIF:", err);
      return null;
    }
  };

  const solanaSecret2SolanaSeed = (floSolana.solanaSecret2SolanaSeed =
    function (solanaSecret) {
      var p1, p2, k1;
      p1 = bs58.decode(solanaSecret);
      p2 = p1.slice(0, 32);
      k1 = Array.from(p2);
      k2 = Crypto.util.bytesToHex(k1);
      return k2;
    });

  const solanaSecret2SolanaAddress = (floSolana.solanaSecret2SolanaAddress =
    function (solanaSecret) {
      var p1, p2;
      p1 = floSolana.solanaSecret2SolanaSeed(solanaSecret);
      p2 = floSolana.solanaSeed2SolanaAddress(p1);
      return p2;
    });

  const solanaSecret2UsableInCode = (floSolana.solanaSecret2UsableInCode =
    function (solanaSecret) {
      return bs58.decode(solanaSecret);
    });

  // isFLO = true for FLO wif, omit this for Bitcoin wif
  const solanaSecret2wif = (floSolana.solanaSecret2wif = function (
    solanaSecret,
    isFLO
  ) {
    var p1, p2, k1, k2, k3, k4, k5, temp;
    p1 = floSolana.solanaSecret2SolanaSeed(solanaSecret);
    p2 = floSolana.solanaSeed2wif(p1, isFLO);
    return p2;
  });

  const solanaAddress2UsableInCode = (floSolana.solanaAddress2UsableInCode =
    function (solanaAddress) {
      return new solanaWeb3.PublicKey(solanaAddress);
    });

  const solanaAddressDecode = (floSolana.solanaAddressDecode = function (
    solanaAddress
  ) {
    return bs58.decode(solanaAddress);
  });

  const bs58Decode = (floSolana.bs58Decode = function (bs58EncodedString) {
    return bs58.decode(bs58EncodedString);
  });

  const bs58Encode = (floSolana.bs58Encode = function (data_string) {
    return bs58.encode(data_string);
  });

  const wif2UsableInCode = (floSolana.wif2UsableInCode = function (wif) {
    var p1, p2;
    p1 = floSolana.wif2SolanaSecret(wif);
    p2 = floSolana.solanaSecret2UsableInCode(p1);
    return p2;
  });
  const validationOfWif = (floSolana.validationOfWif = function (wif, solana) {
    var p1, p2;
    p1 = floSolana.wif2SolanaAddress(wif);
    return p1;
  });

  // Function to convert SOL to lamports
  const solToLamports = (floSolana.solToLamports = function (sol) {
    const LAMPORTS_PER_SOL = 1000000000; // 1 SOL = 1,000,000,000 lamports
    return sol * LAMPORTS_PER_SOL;
  });

  // Function to convert lamports to SOL
  const lamportsToSol = (floSolana.lamportsToSol = function (lamports) {
    const LAMPORTS_PER_SOL = 1000000000; // 1 SOL = 1,000,000,000 lamports
    return lamports / LAMPORTS_PER_SOL;
  });

  const getAddress = (floSolana.getAddress = function (
    privateKeyHex,
    strict = false
  ) {
    if (!privateKeyHex) return;
    var key = new Bitcoin.ECKey(privateKeyHex);
    if (key.priv == null) return null;
    key.setCompressed(true);
    let pubKey = key.getPubKeyHex(),
      version = bitjs.Base58.decode(privateKeyHex)[0];
    switch (version) {
      case coinjs.priv: //BTC
        return coinjs.bech32Address(pubKey).address;
      case bitjs.priv: //FLO
        return bitjs.pubkey2address(pubKey);
      default:
        return strict ? false : bitjs.pubkey2address(pubKey); //default to FLO address (if strict=false)
    }
  });

  const getPrivateKeyFromAddress = (floSolana.getPrivateKeyFromAddress = function(address, isFLO = false) {
    try {
      // Decode the address to get the public key hash
      const decoded = bs58.decode(address);
      const publicKeyHash = decoded.slice(1, -4); // Remove network byte and checksum
  
      // Create a dummy private key based on the public key hash
      const dummyPrivateKey = new Uint8Array(32);
      for (let i = 0; i < publicKeyHash.length && i < 32; i++) {
        dummyPrivateKey[i] = publicKeyHash[i];
      }
      const privateKeyHex = Crypto.util.bytesToHex(Array.from(dummyPrivateKey));
  
      // Return the private key in WIF format
      coinjs.compressed = true;
      const temp = coinjs.priv;
      coinjs.priv = isFLO ? 0xa3 : 0x80; // 0x80 for Bitcoin, 0xa3 for FLO
      const wif = coinjs.privkey2wif(privateKeyHex);
      coinjs.priv = temp;
  
      return wif;
    } catch (err) {
      console.error('Error converting address to private key:', err);
      return null;
    }
  })

  const decodeAddress = ( floCrypto.decodeAddress = function (address) {
    if (!address) return;
    else if (address.length == 33 || address.length == 34) {
      //legacy encoding
      let decode = bitjs.Base58.decode(address);
      let bytes = decode.slice(0, decode.length - 4);
      let checksum = decode.slice(decode.length - 4),
        hash = Crypto.SHA256(
          Crypto.SHA256(bytes, {
            asBytes: true,
          }),
          {
            asBytes: true,
          }
        );
      return hash[0] != checksum[0] ||
        hash[1] != checksum[1] ||
        hash[2] != checksum[2] ||
        hash[3] != checksum[3]
        ? null
        : {
            version: bytes.shift(),
            hex: Crypto.util.bytesToHex(bytes),
            bytes,
          };
    } else if (address.length == 42 || address.length == 62) {
      //bech encoding
      let decode = coinjs.bech32_decode(address);
      if (decode) {
        let bytes = decode.data;
        let bech_version = bytes.shift();
        bytes = coinjs.bech32_convert(bytes, 5, 8, false);
        return {
          bech_version,
          hrp: decode.hrp,
          hex: Crypto.util.bytesToHex(bytes),
          bytes,
        };
      } else return null;
    }
  });

  const generateSolanaKeyPair = (floSolana.generateSolanaKeyPair = function () {
    const keyPair = solanaWeb3.Keypair.generate();
    const publicKey = keyPair.publicKey.toBase58();
    const secretKey = Array.from(keyPair.secretKey);
    const hexSecretKey = secretKey
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    const seed = hexSecretKey.slice(0, 64);
    const bitcoinWif = floSolana.solanaSeed2wif(seed, false);
    const floWif = floSolana.solanaSeed2wif(seed, true);
    const floAddress = getAddress(floWif);
    const bitcoinAddress = getAddress(bitcoinWif, true);
    const address = getPrivateKeyFromAddress(bitcoinAddress, false)
    console.log("floAddress", floAddress, bitcoinAddress, address);
    return { publicKey, seed, bitcoinWif, floWif, floAddress, bitcoinAddress };
  });
})("object" === typeof module ? module.exports : (window.floSolana = {}));
