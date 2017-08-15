# -*- coding: utf-8 -*-
import asyncio
import os

import autobahn

from issues import api
from wamp_utils import WampComponent
from issues.model import Issues, UserIssueData, IssuesModel


class Users(WampComponent):
    pass
    """
    @autobahn.wamp.register('project.example')
    async def example(self, statuses, froms, tos, details):
        con = api.wamp.getConnection(readonly=True)
        try:
            userId = wamp.getWampUser(con, details)
            return Issues.getMyIssues(con, userId, statuses, froms, tos)
        finally:
            con.close()
    """
