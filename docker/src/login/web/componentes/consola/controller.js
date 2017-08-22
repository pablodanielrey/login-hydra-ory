app.controller("ConsolaCtrl", ["$scope", "$location", "$routeParams", "$resource", "$timeout", function ($scope, $location, $routeParams, $resource, $tiemout) {

  // -------------- manejo de pantallas y errores ------------------------------------------------------ //

  $scope.$parent.estado = '';
  $scope.$parent.error = {
    error: '',
    codigo: ''
  }
  $scope.$parent.mensaje = {
    mensaje: '',
    codigo: ''
  };

  $scope.estado_actual = 0;
  $scope.mensaje_actual = 0;

  $scope.estadoSiguiente = function() {
    $scope.estado_actual = ($scope.estado_actual + 1) % $scope.$parent.estados.length;
    $scope.$parent.estado = $scope.$parent.estados[$scope.estado_actual];
  }

  $scope.estadoAnterior = function() {
    $scope.estado_actual = ($scope.estado_actual + $scope.$parent.estados.length - 1) % $scope.$parent.estados.length;
    $scope.$parent.estado = $scope.$parent.estados[$scope.estado_actual];
  }



  $scope.$parent.mensajeSiguiente = function() {
    $scope.mensaje_actual = ($scope.mensaje_actual + 1) % $scope.$parent.mensajes.length;
    $scope.setearMensaje($scope.$parent.mensajes[$scope.mensaje_actual]);
  }

  $scope.$parent.mensajeAnterior = function() {
    $scope.mensaje_actual = ($scope.mensaje_actual + $scope.$parent.mensajes.length - 1) % $scope.$parent.mensajes.length;
    $scope.setearMensaje($scope.$parent.mensajes[$scope.mensaje_actual]);
  }

  $scope.$parent.limpiarMensaje = function() {
    $scope.$parent.mensaje = {
      mensaje: '',
      codigo:''
    }
  }

  $scope.$parent.setearMensaje = function(m) {
    $scope.$parent.mensaje = {
      mensaje: 'mensaje',
      codigo: m
    }
  }

  $scope.$parent.cambiarMensaje = function() {
    if ($scope.$parent.mensaje.mensaje == '') {
      $scope.$parent.mensaje.mensaje = 'mensaje';
    } else {
      $scope.$parent.mensaje.mensaje = '';
    }
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

  $scope.$parent.cambiarError = function() {
    if ($scope.$parent.error.error == '') {
      $scope.$parent.error.error = 'error';
    } else {
      $scope.$parent.error.error = '';
    }
  }

  $scope.$parent.errorSiguiente = function() {
    $scope.error_actual = ($scope.error_actual + 1) % $scope.errores_posibles.length;
    $scope.$parent.error = {
      error: 'error',
      codigo: $scope.$parent.errores_posibles[$scope.error_actual]
    };
  }

  $scope.$parent.errorAnterior = function() {
    $scope.error_actual = ($scope.error_actual + $scope.errores_posibles.length - 1) % $scope.errores_posibles.length;
    $scope.$parent.error = {
      error: 'error',
      codigo: $scope.$parent.errores_posibles[$scope.error_actual]
    };
  }

}]);
  ////////

  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
