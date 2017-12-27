
tutorial de referencia en parte.
https://www.ory.am/run-oauth2-server-open-source-api-security



IMPORTANTE!!!:
se deben crear crear las carpetas para los vólumenes definidos en stack.yml


inicialmente para configurar los clientes y el consent-app dentro de en hydra (solo una vez por base de datos)
ejecutar los scripts para agregar los clientes y el consent-app definidos dentro del archivo
hydra_init/init_hydra

usando init-cluster.sh se puede ejcutar uncontenedor hydra para realizar la migración de la base inicial
y ejecutar tales scripts de inicialización.
ANTES de ejecutar cada uno de los scripts DEBE conectar hydra usanod el comando (dentro del contenedor de hydra):

hydra connect

y pedirá los datos de url del servidor hydra.
y usuario y clave. (definidos en stack.yml como variables de entorno del hydra)

ej:
https://127.0.0.1:4444
admin
demo-password
-----


tambien para que las redirecciones funcionen correctamente DEBE definir los siguientes dns usando
el /etc/hosts de SU PC para su explorador.
y editando el archivo
bind/zones/db.local
para que los dockers resuelvan las redirecciones correctamente.
tambien debe editar
stack.yml
ajustando la ip definida como config del dns, (debe ser una ip)

!!!!!!!!!!!!!!!!!!!!!!!!
TODO con la misma ip externa de la pc donde va a ejecutar el stack.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

hay que definir los siguientes nombres de dominio dentro de hosts (192.168.0.3 es un ejemplo de ip externa)

192.168.0.3   hydra.dominio
192.168.0.3   consent.dominio
192.168.0.3   client.dominio


para probar los ejemplos se debe ejecutar chrome usando el flag.
--ignore-certificate-errors
ya que se usan certs autofirmados asi no tira error.


la url a acceder es:
https://client.dominio

con eso dispara el flujo de redirecciones y de autorizaciones.


-----
