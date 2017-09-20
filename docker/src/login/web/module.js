app = angular.module('MainApp', ['ui.router'])


app.config(['$stateProvider', '$urlRouterProvider', function($stateProvider, $urlRouterProvider) {

  $urlRouterProvider.otherwise("/login");

  // --- preload ----

  $stateProvider
  .state('login', {
    url:'/login',
    templateUrl: 'componentes/login/index.html',
    controller:'LoginCtrl'
  })
  .state('login.login', {
    url:'/login_login',
    templateUrl: 'componentes/login/templates/login.html',
    controller:'LoginCtrl'
  })
  .state('login.SistemaError', {
    url:'/sistema_error',
    templateUrl: 'componentes/login/templates/error_sistema.html',
  })
  .state('login.SeguridadError', {
    url:'/seguridad_error',
    templateUrl: 'componentes/login/templates/error_seguridad.html',
  })


}]);


// app.config(['$resourceProvider', function($resourceProvider) {
//   $resourceProvider.defaults.stripTrailingSlashes = false;
// }]);
