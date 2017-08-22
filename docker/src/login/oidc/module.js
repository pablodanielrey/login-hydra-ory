app = angular.module('MainApp', ['ngRoute', 'ngResource'])

app.config(['$routeProvider', function($routeProvider) {

  $routeProvider
    .when('/login', {templateUrl: '/componentes/login/index.html', controller:'LoginCtrl'})
    .otherwise({ redirectTo: '/login' });

}]);

app.config(['$resourceProvider', function($resourceProvider) {
  $resourceProvider.defaults.stripTrailingSlashes = false;
}]);
