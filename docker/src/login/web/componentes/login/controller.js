
app.controller("LoginCtrl", ["$scope", "$location", "$routeParams", "$resource", "$timeout","$http", "$window", function ($scope, $location, $routeParams, $resource, $timeout, $http, $window) {

  // -------------- manejo de pantallas y errores ------------------------------------------------------ //
  $scope.$parent.errores_posibles = ['UsuarioBloqueadoError','UsuarioNoEncontradoError', 'ClaveError', 'SeguridadError', 'SistemaError'];
  $scope.$parent.mensajes = [];

  $scope.$parent.estados = ['Estado_Login','Estado_Redireccionando'];
  $timeout(function() {
    $scope.$parent.estado = 'Estado_Login';
    $scope.$parent.mensaje = {mensaje:'', codigo:''};
  });
  //////////////////
  //
  // $scope.errores_internos = ['', 'error_de_primer_acceso' , 'error_reiterado_de_acceso', 'error_usuario_bloqueado'];
  // $scope.error_interno = 'error_usuario_bloqueado';

  $scope.model = {
    intentos_restantes: 5
  }

  /*
  $scope.restar_intentos = function() {
    $scope.model.intentos_restantes = $scope.model.intentos_restantes - 1;
    if ($scope.model.intentos_restantes > 0) {
      $timeout($scope.restar_intentos, 1000);
    } else {
      $scope.$parent.setearError({error:'UsuarioBloqueadoError'});
    }
  }
  $timeout($scope.restar_intentos,1000);
*/

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
            data: data,
            withCredentials: true
        });
    };


  $scope.login = function() {
    $scope._postData('/login', {'u':$scope.usuario, 'p':$scope.clave})
            .then(function(data) {
                console.log(data);
                // $scope.usuario = data.data.usuario;
                // $scope.$parent.estadoSiguiente();
                // $timeout(function() {
                //   $window.location.href = data.data.url;
                // },1500);
                $timeout(function() {
                   $window.location.href = data.data.url;
                });

             }).catch(function(data) {
               console.log(data);


               if (data.data == null) {
                 $scope.$parent.setearError({error:'SistemaError'});
                 return;
               }

               if (data.data.error == 'UsuarioBloqueadoError') {
                 $scope.model.tiempo_de_bloqueo = data.data.data.tiempo_de_bloqueo;
               }

               if (data.data.error == 'ClaveError') {
                 $scope.model.intentos_restantes = data.data.data.intentos_restantes;
               }

               $scope.$parent.setearError(data.data);

             });
  }



}]);
