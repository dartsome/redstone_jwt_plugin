import 'package:jwt/json_web_token.dart';
import "package:symcrypt/symcrypt.dart" as Symcrypt;

abstract class AuthHelper {
  String get TokenName;
  String get TokenSecret;
  Duration get TokenDuration;
  String get PasswordSalt;

  JsonWebTokenCodec _jwt;

  AuthHelper() {
    _jwt = new JsonWebTokenCodec(secret: TokenSecret, header: {"alg": "HS256", "typ": "JWT"});
  }

  String issueToken(String uniqueKey, {Map<String, dynamic> payload: const {}, int role: 0, Duration duration}) {
    DateTime exp = new DateTime.now();
    if (duration == null) {
      duration = TokenDuration;
    }
    exp = exp.add(duration);

    Map<String, dynamic> _payload = {'iss': uniqueKey, 'exp': exp.millisecondsSinceEpoch, "role": role};
    _payload.addAll(payload);
    return _jwt.encode(_payload);
  }

  bool isTokenValid(String token) {
    if (token == null || !_jwt.isValid(token)) {
      return false;
    }
    Map _token = decodeToken(token);
    return _token.containsKey("exp") && _token["exp"] >= new DateTime.now().millisecondsSinceEpoch;
  }

  bool checkRole(String token, int role) {
    Map _token = decodeToken(token);
    return _token["role"] >= role;
  }

  Map decodeToken(String token) => _jwt.decode(token);

  String hashPassword(String password) => Symcrypt.createHash(Symcrypt.saltData(password, PasswordSalt));
}
