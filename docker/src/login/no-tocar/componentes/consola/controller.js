app.controller("ConsolaCtrl", ["$scope", "$location", "$routeParams", "$resource", "$timeout", function ($scope, $location, $routeParams, $resource, $tiemout) {

  // -------------- manejo de pantallas y errores ------------------------------------------------------ //

  $scope.$parent.estilo = '';
  $scope.$parent.error = {
    error: '',
    codigo: ''
  }


  $scope.estilo_actual = 0;

  $scope.$parent.pasoSiguiente = function() {
    $scope.estilo_actual = ($scope.estilo_actual + 1) % $scope.estilos.length;
    $scope.$parent.estilo = $scope.$parent.estilos[$scope.estilo_actual];
  }

  $scope.$parent.pasoAnterior = function() {
    $scope.estilo_actual = ($scope.estilo_actual + $scope.estilos.length - 1) % $scope.estilos.length;
    $scope.$parent.estilo = $scope.$parent.estilos[$scope.estilo_actual];
  }


  $scope.$parent.limpiarError = function() {
    $scope.$parent.error = {
      error: '',
      codigo: ''
    }
  }

  $scope.$parent.setearError = function(e) {
    $scope.$parent.error = {
      error: 'error',
      codigo: e.error
    };
  }

  $scope.error_actual = 0;

  $scope.cambiarError = function() {
    if ($scope.$parent.error.error == '') {
      $scope.$parent.error.error = 'error';
    } else {
      $scope.$parent.error.error = '';
    }
  }

  $scope.errorSiguiente = function() {
    $scope.error_actual = ($scope.error_actual + 1) % $scope.errores_posibles.length;
    $scope.$parent.error = {
      error: 'error',
      codigo: $scope.$parent.errores_posibles[$scope.error_actual]
    };
  }

  $scope.errorAnterior = function() {
    $scope.error_actual = ($scope.error_actual + $scope.errores_posibles.length - 1) % $scope.errores_posibles.length;
    $scope.$parent.error = {
      error: 'error',
      codigo: $scope.$parent.errores_posibles[$scope.error_actual]
    };
  }

}]);
  ////////

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
