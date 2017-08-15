import os
import logging
from autobahn.asyncio.wamp import ApplicationRunner

from issues.api.wamp import Issues

import txaio
txaio.use_asyncio()
txaio.start_logging(level='debug')

if __name__ == '__main__':
    logging.info('Ejecuando loop')

    runner = ApplicationRunner(
        url=os.environ['CROSSBAR_URL'],
        realm=os.environ['CROSSBAR_REALM']
    )

    runner.run(Issues)
