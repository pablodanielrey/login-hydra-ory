
app.controller("HeaderCtrl", ["$scope", "$location", "$resource", "$timeout", "$window", function ($scope, $location, $resource, $tiemout, $window) {

  $scope.view = {
    logo: '/img/usersico.gif',
    usuario: null
  };

  $scope.salir = function() {
    $window.location.href = '/logout';
  }

  $scope.$on('config', function(c) {
    $scope.view.usuario = $scope.$parent.config.usuario;
  });

}]);
