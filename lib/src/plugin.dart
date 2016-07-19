import "dart:io";
import "package:redstone/redstone.dart" as app;
import "package:di/di.dart";
import "security.dart";
import "auth_helper.dart";

class DecodeToken {
  const DecodeToken();
}

app.RedstonePlugin RedstoneJwtPlugin(Type authService) {
  return (app.Manager manager) {
    manager.addRouteWrapper(AuthRequire, (wrap, Injector injector, request, route) async {
      AuthRequire security = wrap as AuthRequire;
      AuthHelper helper = injector.get(authService);
      String token = request.headers[helper.TokenName];

      if (helper.isTokenValid(token) && helper.checkRole(token, security.role)) {
        return route(injector, request);
      }
      throw new app.ErrorResponse(HttpStatus.UNAUTHORIZED, {"error": "Unauthorized"});
    }, includeGroups: true);

    manager.addParameterProvider(DecodeToken, (metadata, type, handlerName, paramName, request, injector) {
      AuthHelper helper = injector.get(authService);
      if (request.headers.containsKey(helper.TokenName)) {
        return helper.decodeToken(request.headers[helper.TokenName]);
      }
      return null;
    });
  };
}
