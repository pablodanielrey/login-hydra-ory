
app.controller("LoginCtrl", ["$scope", "$location", "$timeout","$http", "$window", "$state", function ($scope, $location, $timeout, $http, $window, $state) {

  $scope.model = {
    intentos_restantes: 5
  }

  $scope.error = {
    error: ""
  };

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


  $scope.limpiar_error = function() {
    $scope.error.error = '';
  }


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
                $timeout(function() {
                   $window.location.href = data.data.url;
                });

             }).catch(function(data) {
               console.log(data);
               $scope.setearError(data.data);

               if (data.data == null) {
                 $scope.$parent.setearError({error:'SistemaError'});
                 return;
               }

               $scope.error.error = data.data.error;

               if (data.data.error == 'UsuarioBloqueadoError') {
                 $scope.model.tiempo_de_bloqueo = data.data.data.tiempo_de_bloqueo;
               }

               if (data.data.error == 'ClaveError') {
                 //$scope.model.intentos_restantes = data.data.data.intentos_restantes;
                 $scope.model.intentos_restantes = 0;
               }

               $scope.$parent.setearError(data.data);

             });
  }


  $scope.setearError = function(err) {
    $state.go('login.' + err.error);
  }

  $state.go('login.login');

}]);
