import "dart:async";
import "dart:io";
import 'package:redstone/redstone.dart' as Redstone;
import "package:di/di.dart";
import "package:redstone_jwt_plugin/redstone_jwt_plugin.dart";

main() {
  Redstone.showErrorPage = false;

  Redstone.addModule(new Module()..bind(AuthService));

  /// Add RedstoneJwtPlugin
  Redstone.addPlugin(RedstoneJwtPlugin(AuthService));

  Redstone.start();

}

const String BasicUser = "basic";
const String ProUser = "pro";

const List<String> Audience = const [ BasicUser, ProUser ];

List<User> users = <User>[];
int idGenerator = 0;

class User {
  String username;
  String password;
  List<String> rights;
  int id = idGenerator++;
}

@Redstone.Group("/auth")
class AuthService extends JwtProvider with AuthenticationProvider {

  /// Token Name in the request header
  @override
  String get TokenName => "MyToken";

  /// Use to salt the password of an User
  @override
  String get PasswordSalt => "MyPasswordSalt";

  @override
  Duration get TokenDuration => const Duration(days: 7);

  /// Use to encrypt the JwtToken
  @override
  String get TokenSecret => "MyTokenSecret";

  @Redstone.Route("/login", methods: const [ Redstone.POST])
  Future<Map<String, dynamic>> login(@Redstone.Body(Redstone.JSON) Map body) async {
    String username = body["username"];
    String password = hashPassword(body["password"]);

    User user = users.firstWhere((User usr) => usr.username == username && usr.password == password, orElse: () => null);
    if (user == null) {
      throw new Redstone.ErrorResponse(HttpStatus.UNAUTHORIZED, {"error": "Authentication error"});
    }
    return {"token": issueToken("issuer:RedstoneJwtPlugin", username, audience: user.rights)};
  }

  @Redstone.Route("/register", methods: const [ Redstone.POST])
  register(@Redstone.Body(Redstone.JSON) Map body) {
    String username = body["username"];
    String password = hashPassword(body["password"]);
    String right = body["right"];
    if (!Audience.contains(right)) {
      right = BasicUser;
    }

    User user = new User();
    user.username = username;
    user.password = password;
    user.rights = [ right ];

    User foundUser = users.firstWhere((User usr) => usr.username == username, orElse: () => null);
    if (foundUser != null) {
      throw new Redstone.ErrorResponse(HttpStatus.BAD_REQUEST, {"error": "Username already exist"});
    }
    users.add(user);
  }

  @AuthRequire(audience: Audience) /// Every auth User can access to this route
  @Redstone.Route('/connectedUser', methods: const [ Redstone.GET])
  Future<Map<String, dynamic>> connectedUser(@DecodeToken() Map token) async {
    User user = users.firstWhere((User usr) => usr.username == token["sub"], orElse: () => null);
    if (user == null) {
      throw new Redstone.ErrorResponse(HttpStatus.BAD_REQUEST, {"error": "User does not exist"});
    }
    return {
      "username": user.username,
      "id": user.id,
      "rights": user.rights
    };
  }

  @AuthRequire(audience: const [ ProUser ]) /// Every auth User can access to this route
  @Redstone.Route('/connectedProUser', methods: const [ Redstone.GET])
  Future<Map<String, dynamic>> connectedProUser(@DecodeToken() Map token) async {
    User user = users.firstWhere((User usr) => usr.username == token["sub"], orElse: () => null);
    if (user == null) {
      throw new Redstone.ErrorResponse(HttpStatus.BAD_REQUEST, {"error": "User does not exist"});
    }
    return {
      "username": user.username,
      "id": user.id,
      "rights": user.rights
    };
  }


}