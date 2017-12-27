
tutorial de referencia
https://www.ory.am/run-oauth2-server-open-source-api-security

hay que definir los siguientes nombres de dominio dentro de hosts

192.168.0.3   hydra.dominio
192.168.0.3   consent.dominio
192.168.0.3   client.dominio


se debe ejecutar chrome usando el flag.
--ignore-certificate-errors
ya que se usan certs autofirmados

obviamente cambiando la ip a la ip externa que se tenga en la pc.
despues ejecutar los scripts para agregar los clientes y el consent-app
definidos dentro de init_hydra

usando init-cluster.sh se puede ejcutar uncontenedor hydra para realizar la migración de la base inicial.


hay que crear las carpetas para los vólumenes de stack.yml
