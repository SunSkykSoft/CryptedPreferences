import 'package:encrypt/encrypt.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Key/Value 型のデータを暗号化して SharedPreferences を使って読み書きするクラス.
/// AES 暗号化に利用する Key と IV は SecureStorage に保存する.
/// SharedPreferences で利用できるデータ型は以下の通り.
///  - String : 暗号化対象。暗号化しない場合は noCrypt を true にする.
///  - List<String> : 暗号化対象。暗号化しない場合は noCrypt を true にする.
///  - bool : 暗号化対象外
///  - int : 暗号化対象外
///  - double : 暗号化対象外
class CryptedPreferences {

  // Singleton
  static final CryptedPreferences _instance = CryptedPreferences._internal();
  factory CryptedPreferences() {
    return _instance;
  }
  CryptedPreferences._internal();

  /// SecureStorage
  final secureStorage = const FlutterSecureStorage();

  /// SharedPreferencesAsync (shared_preferences v2.3.0 以降)
  final prefs = SharedPreferencesAsync();

  /// [Key] を取得する
  /// SecureStorage に Key が存在しない場合は生成する.
  Future<Key> _getKey() async {
    String? key = await secureStorage.read(key: 'key');
    if (key == null) {
      key = Key.fromLength(32).base64;
      await secureStorage.write(key: 'key', value: key);
    }
    return Key.fromBase64(key);
  }

  /// [IV] を取得する
  /// SecureStorage に IV が存在しない場合は生成する.
  Future<IV> _getIV() async {
    String? iv = await secureStorage.read(key: 'iv');
    if (iv == null) {
      iv = IV.fromLength(16).base64;
      await secureStorage.write(key: 'iv', value: iv);
    }
    return IV.fromBase64(iv);
  }

  /// 文字列 [plainText] を暗号化し base64 文字列として返す.
  Future<String> _encrypt(String plainText) async {
    final key = await _getKey();
    final iv = await _getIV();
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: 'PKCS7'));

    final encrypted = encrypter.encrypt(plainText, iv: iv);
    return encrypted.base64;
  }

  /// 暗号化された文字列 [encryptedBase64Text] を復号する.
  /// 復号に失敗した場合は null を返す.
  Future<String?> _decrypt(String encryptedBase64Text) async {
    final key = await _getKey();
    final iv = await _getIV();
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: 'PKCS7'));

    String? plainText;
    try {
      plainText = encrypter.decrypt(Encrypted.fromBase64(encryptedBase64Text), iv: iv);
    } catch (e) {
      print('Failed to decrypt: $e');
    }
    return plainText;
  }

  /// 指定された [key] で SharedPreferences に保存された文字列を取得し、復号して返す.
  Future<String?> getString(String key, {bool noCrypt = false}) async {
    var encryptedBase64Text = await prefs.getString(key);
    // print('encryptedBase64Text: $encryptedBase64Text');

    // 暗号化しない場合はそのまま返す.
    if (noCrypt) {
      return encryptedBase64Text;
    }
    // 暗号化された文字列を復号して返す.
    if (encryptedBase64Text != null) {
      return await _decrypt(encryptedBase64Text);
    }
    return null;
  }

  /// 指定された [key] で SharedPreferences に文字列 [value] を暗号化して保存する.
  /// [noCrypt] が true の場合は暗号化せずに保存する.
  Future<void> setString(String key, String value, {bool noCrypt = false}) async {
    if (noCrypt) {
      // 暗号化しない場合はそのまま保存する.
      await prefs.setString(key, value);
    } else {
      // 暗号化して保存する.
      var encryptedBase64Text = await _encrypt(value);
      await prefs.setString(key, encryptedBase64Text);
      // print('encryptedBase64Text: $encryptedBase64Text');
    }
  }

  /// 指定された [key] で SharedPreferences に保存された文字列リストを取得し、復号して返す.
  Future<List<String>?> getStringList(String key, {bool noCrypt = false}) async {
    var encryptedBase64TextList = await prefs.getStringList(key);

    // 暗号化しない場合はそのまま返す.
    if (noCrypt) {
      return encryptedBase64TextList;
    }

    // 暗号化された文字列を復号して返す.
    if (encryptedBase64TextList != null) {
      List<String> plainTextList = [];
      for (var encryptedBase64Text in encryptedBase64TextList) {
        var plainText = await _decrypt(encryptedBase64Text);
        if (plainText != null) {
          plainTextList.add(plainText);
        }
      }
      return plainTextList;
    }
    return null;
  }

  /// 指定された [key] で SharedPreferences に文字列リスト [value] を暗号化して保存する.
  /// [noCrypt] が true の場合は暗号化せずに保存する.
  Future<void> setStringList(String key, List<String> value, {bool noCrypt = false}) async {
    if (noCrypt) {
      // 暗号化しない場合はそのまま保存する.
      await prefs.setStringList(key, value);
    } else {
      // 暗号化して保存する.
      List<String> encryptedBase64TextList = [];
      for (var plainText in value) {
        var encryptedBase64Text = await _encrypt(plainText);
        encryptedBase64TextList.add(encryptedBase64Text);
      }
      await prefs.setStringList(key, encryptedBase64TextList);
    }
  }

  /// 指定された [key] に bool値 [value] を保存する.
  Future<void> setBool(String key, bool value) async {
    await prefs.setBool(key, value);
  }

  /// 指定された [key] に int値 [value] を保存する.
  Future<void> setInt(String key, int value) async {
    await prefs.setInt(key, value);
  }

  /// 指定された [key] に double値 [value] を保存する.
  Future<void> setDouble(String key, double value) async {
    await prefs.setDouble(key, value);
  }

  /// SharedPreferences の [key] に保存された bool値を取得する.
  Future<bool?> getBool(String key) async {
    return await prefs.getBool(key);
  }

  /// SharedPreferences の [key] に保存された int値を取得する.
  Future<int?> getInt(String key) async {
    return await prefs.getInt(key);
  }

  /// SharedPreferences の [key] に保存された double値を取得する.
  Future<double?> getDouble(String key) async {
    return await prefs.getDouble(key);
  }

  /// SharedPreferences に保存された [key] で指定されたエントリを削除する.
  Future<void> remove(String key) async {
    await prefs.remove(key);
  }

}
