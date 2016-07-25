import "package:dart_jwt/dart_jwt.dart";
import "package:crypto/crypto.dart" as Crypto;

abstract class AuthenticationProvider {
  String get PasswordSalt;

  String hashPassword(String password) {
    String saltedPassword = password + PasswordSalt;
    Crypto.Digest digest = Crypto.md5.convert(saltedPassword.codeUnits);
    return new String.fromCharCodes(digest.bytes);
  }
}

abstract class JwtProvider {
  String get TokenName;
  String get TokenSecret;
  Duration get TokenDuration;

  JwaSignatureContext _signatureContext;


  JwtProvider() {
    _signatureContext = new JwaSymmetricKeySignatureContext(TokenSecret);
  }

  String issueToken(String issuer, String subject, {Duration duration, List<String> audience}) {
    DateTime issuedAt = new DateTime.now();
    if (duration == null) {
      duration = TokenDuration;
    }
    DateTime expiry = issuedAt.add(duration);
    final claimSet = new OpenIdJwtClaimSet.build(
      issuer: issuer,
      subject: subject,
      audience: audience,
      expiry: expiry,
      issuedAt: issuedAt);
    JsonWebToken jwt = new JsonWebToken.jws(claimSet, _signatureContext);
    return jwt.encode();
  }

  String issuerCustomToken(JwtClaimSet claimSet, {JwaSignatureContext signatureContext}) {
    JsonWebToken jwt = new JsonWebToken.jws(claimSet, signatureContext ?? _signatureContext);
    return jwt.encode();
  }

  bool isTokenValid(String token, List<String> audience) {
    if (token == null) {
      return false;
    }
    JsonWebToken jwt = decodeToken(token);
    OpenIdJwtClaimSet claimSet = jwt.claimSet;
    Set<ConstraintViolation> violations = claimSet.validate(const JwtClaimSetValidationContext());
    if (violations.isEmpty) {
      for (String aud in claimSet.audience) {
        if (audience.contains(aud)) {
          return true;
        }
      }
    }
    return false;
  }


  JsonWebToken decodeToken(String token) =>  new JsonWebToken.decode(token);

}

