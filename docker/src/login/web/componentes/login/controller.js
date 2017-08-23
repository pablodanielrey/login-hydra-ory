
app.controller("LoginCtrl", ["$scope", "$location", "$routeParams", "$resource", "$timeout","$http", "$window", function ($scope, $location, $routeParams, $resource, $timeout, $http, $window) {

  // -------------- manejo de pantallas y errores ------------------------------------------------------ //
  $scope.$parent.errores_posibles = ['UsuarioBloqueadoError','UsuarioInexistenteError','SeguridadError', 'SistemaError'];
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
               } else {
                 $scope.$parent.setearError(data.data);
               }
             });
  }



}]);
