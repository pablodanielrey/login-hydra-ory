from autobahn.wamp.types import CallOptions, RegisterOptions
from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner

class WampComponent(ApplicationSession):

    def getLogger(self):
        return logging.getLogger('{}.{}'.format(self.__module__, self.__class__.__name__))

    def getRegisterOptions(self):
        return RegisterOptions(details_arg='details')

    """
    def __init__(self, config = None):
        ApplicationSession.__init__(self, config)
    """

    async def onJoin(self, details):
        logging.info('Registrando procesos')
        results = await self.register(self, options=self.getRegisterOptions())
        results = await self.subscribe(self)
