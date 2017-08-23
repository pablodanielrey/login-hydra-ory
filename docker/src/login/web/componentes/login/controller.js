
app.controller("LoginCtrl", ["$scope", "$location", "$routeParams", "$resource", "$timeout","$http", function ($scope, $location, $routeParams, $resource, $timeout, $http) {

  // -------------- manejo de pantallas y errores ------------------------------------------------------ //
  $scope.$parent.errores_posibles = ['UsuarioBloqueadoError','UsuarioInexistenteError','SeguridadError'];
  $scope.$parent.mensajes = [];

  $scope.$parent.estados = ['Estado_Login','Estado_Redireccionando'];
  $timeout(function() {
    $scope.$parent.estado = 'Estado_Login';
    $scope.$parent.mensaje = {mensaje:'', codigo:''};
  });
  //////////////////


  /*
    hace post de los datos en urlencoded formato. a la url especificada
    usanod el challenge si esta seteado
  */
  $scope._postData = function(url, data) {
    return $http({
            url: url,
            method: "POST",
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            transformRequest: function(obj) {
                var str = [];
                for(var p in obj)
                str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
                return str.join("&");
            },
            data: data
        });
    };

  $scope.enviarDni = function() {
    $scope._postData('/verificar', {'u':$scope.usuario})
            .then(function(data, status, headers, config) {
                $scope.$parent.pasoSiguiente();
             }).catch(function(data, status, headers, config) {
               console.log(data);
               $scope.$parent.setearError(data.data);
             });
  };


  $scope.login = function() {
    $scope._postData('/login', {'u':$scope.usuario, 'p':$scope.clave})
            .then(function(data, status, headers, config) {
                console.log(data);
                console.log(status);
                console.log(headers);
                console.log(config);
                $scope.$parent.pasoSiguiente();
                $timeout(function() {
                  $scope.redirigir();
                },5);
             }).catch(function(data, status, headers, config) {
               console.log(data);
               $scope.$parent.setearError(data.data);
             });
  }

  $scope.redirigir = function() {
    $http({url: '/consent', method: "GET", params: {challenge: $scope.challenge}})
         .then(function(data, status, headers, config) {
           console.log(data);
         })
         .catch(function(data, status, headers, config) {
           console.log(data);
         });
  }


}]);
