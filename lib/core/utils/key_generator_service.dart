import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

class KeyGeneratorService {
  final SecureRandom _secureRandom = FortunaRandom();
  bool _isInitialized = false;

  Future<void> initialize() async {
    if (_isInitialized) return;

    // تهيئة مولد الأرقام العشوائية الآمن
    final seedSource = _createCryptographicallySecureSeed();
    _secureRandom.seed(KeyParameter(seedSource));

    _isInitialized = true;
  }

  /// توليد مفتاح AES
  Future<Uint8List> generateAesKey({int bits = 256}) async {
    if (!_isInitialized) await initialize();

    final keyBytes = bits ~/ 8;
    final key = Uint8List(keyBytes);
    _secureRandom.nextBytes(keyBytes, key);

    return key;
  }

  /// توليد زوج مفاتيح RSA
  Future<AsymmetricKeyPair<PublicKey, PrivateKey>> generateRsaKeyPair({int bits = 4096}) async {
    if (!_isInitialized) await initialize();

    final keyParams = RSAKeyGeneratorParameters(BigInt.parse('65537'), bits, 64);
    final keyGenerator = RSAKeyGenerator();
    keyGenerator.init(ParametersWithRandom(keyParams, _secureRandom));

    return keyGenerator.generateKeyPair();
  }

  /// توليد زوج مفاتيح ECDSA
  Future<AsymmetricKeyPair<PublicKey, PrivateKey>> generateEcdsaKeyPair({String curve = 'secp256r1'}) async {
    if (!_isInitialized) await initialize();

    final domainParams = ECDomainParameters(curve);
    final keyParams = ECKeyGeneratorParameters(domainParams);

    final keyGenerator = ECKeyGenerator();
    keyGenerator.init(ParametersWithRandom(keyParams, _secureRandom));

    return keyGenerator.generateKeyPair();
  }

  /// توليد مفتاح HMAC
  Future<Uint8List> generateHmacKey({int bits = 256}) async {
    if (!_isInitialized) await initialize();

    final keyBytes = bits ~/ 8;
    final key = Uint8List(keyBytes);
    _secureRandom.nextBytes(keyBytes, key);

    return key;
  }

  /// توليد salt للتشفير
  Future<Uint8List> generateSalt({int length = 16}) async {
    if (!_isInitialized) await initialize();

    final salt = Uint8List(length);
    _secureRandom.nextBytes(length, salt);

    return salt;
  }

  /// توليد IV لتشفير AES
  Future<Uint8List> generateIv({int length = 12}) async {
    if (!_isInitialized) await initialize();

    final iv = Uint8List(length);
    _secureRandom.nextBytes(length, iv);

    return iv;
  }

  /// اشتقاق مفتاح من كلمة مرور
  Future<Uint8List> deriveKeyFromPassword(
      String password,
      Uint8List salt, {
        int iterations = 100000,
        int keyLength = 32,
      }) async {
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));
    pbkdf2.init(Pbkdf2Parameters(salt, iterations, keyLength));

    return pbkdf2.process(Uint8List.fromList(utf8.encode(password)));
  }

  /// توليد مفتاح جلسة
  Future<String> generateSessionKey({int length = 32}) async {
    if (!_isInitialized) await initialize();

    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    final random = Random.secure();

    return List.generate(length, (_) => chars[random.nextInt(chars.length)]).join();
  }

  /// توليد مفتاح API
  Future<String> generateApiKey({String prefix = 'sk'}) async {
    if (!_isInitialized) await initialize();

    final key = await generateSessionKey(length: 32);
    final timestamp = DateTime.now().millisecondsSinceEpoch.toString().substring(5);

    return '${prefix}_${timestamp}_$key';
  }

  /// توليد زوج مفاتيح Ed25519
  Future<AsymmetricKeyPair<PublicKey, PrivateKey>> generateEd25519KeyPair() async {
    if (!_isInitialized) await initialize();

    final keyParams = Ed25519KeyGeneratorParameters();
    final keyGenerator = Ed25519KeyGenerator();
    keyGenerator.init(ParametersWithRandom(keyParams, _secureRandom));

    return keyGenerator.generateKeyPair();
  }

  /// تشفير المفتاح الخاص
  Future<String> encryptPrivateKey(
      PrivateKey privateKey,
      String password,
      ) async {
    // تحويل المفتاح إلى بايتات
    final privateKeyBytes = _encodePrivateKey(privateKey);

    // توليد salt
    final salt = await generateSalt();

    // اشتقاق مفتاح التشفير من كلمة المرور
    final encryptionKey = await deriveKeyFromPassword(password, salt);

    // توليد IV
    final iv = await generateIv();

    // تشفير المفتاح
    final cipher = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(
        KeyParameter(encryptionKey),
        128,
        iv,
        Uint8List(0),
      ));

    final encryptedKey = cipher.process(privateKeyBytes);

    // دمج البيانات
    final result = {
      'salt': base64.encode(salt),
      'iv': base64.encode(iv),
      'encryptedKey': base64.encode(encryptedKey),
    };

    return json.encode(result);
  }

  /// فك تشفير المفتاح الخاص
  Future<PrivateKey> decryptPrivateKey(
      String encryptedData,
      String password,
      ) async {
    final data = json.decode(encryptedData);

    final salt = base64.decode(data['salt']);
    final iv = base64.decode(data['iv']);
    final encryptedKey = base64.decode(data['encryptedKey']);

    // اشتقاق مفتاح فك التشفير
    final decryptionKey = await deriveKeyFromPassword(password, salt);

    // فك التشفير
    final cipher = GCMBlockCipher(AESEngine())
      ..init(false, AEADParameters(
        KeyParameter(decryptionKey),
        128,
        iv,
        Uint8List(0),
      ));

    final decryptedKeyBytes = cipher.process(encryptedKey);

    // تحويل البايتات إلى مفتاح خاص
    return _decodePrivateKey(decryptedKeyBytes);
  }

  Uint8List _createCryptographicallySecureSeed() {
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final random = Random.secure();
    final seed = Uint8List(32);

    for (int i = 0; i < seed.length; i++) {
      seed[i] = random.nextInt(256);
    }

    // إضافة الختم الزمني للعشوائية
    final timestampBytes = ByteData(8)..setInt64(0, timestamp);
    for (int i = 0; i < 8; i++) {
      seed[i] ^= timestampBytes.getUint8(i);
    }

    return seed;
  }

  Uint8List _encodePrivateKey(PrivateKey privateKey) {
    // تنفيذ الترميز حسب نوع المفتاح
    if (privateKey is RSAPrivateKey) {
      return _encodeRSAPrivateKey(privateKey);
    } else if (privateKey is ECPrivateKey) {
      return _encodeECPrivateKey(privateKey);
    }

    throw UnsupportedError('Unsupported private key type');
  }

  PrivateKey _decodePrivateKey(Uint8List bytes) {
    // تنفيذ فك الترميز حسب نوع المفتاح
    // يجب تحديد نوع المفتاح من البايتات
    throw UnimplementedError();
  }

  Uint8List _encodeRSAPrivateKey(RSAPrivateKey key) {
    // ترميز مفتاح RSA الخاص
    // يتطلب تنفيذ ASN.1 DER encoding
    throw UnimplementedError();
  }

  Uint8List _encodeECPrivateKey(ECPrivateKey key) {
    // ترميز مفتاح EC الخاص
    // يتطلب تنفيذ ASN.1 DER encoding
    throw UnimplementedError();
  }
}