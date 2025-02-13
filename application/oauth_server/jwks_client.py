from typing import Any

import requests
import logging
from jwt import PyJWKClient, PyJWKClientError
from requests_cache import CachedSession


logger = logging.getLogger('CacheHeaderPyJWKClient')

class CacheHeaderPyJWKClient(PyJWKClient):
    def __init__(self,
                 uri: str,
                 backend='memory'
                 ):
        super(CacheHeaderPyJWKClient, self).__init__(uri, False, 0, False, 0)
        self.session = CachedSession('jwks_cache', cache_control=True, backend=backend)

    def fetch_data(self) -> Any:
        with self.session.get(self.uri) as response:
            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError as e:
                    raise PyJWKClientError(f'Fail parse data from the url, err: "{e}"')
            else:
                ## Hack fix for VECOZO not accepting the `Python-urllib/3.8` User-Agent
                if response.status_code >= 400 < 500:
                    user_agent = "Mozilla/5.0"
                    logger.warning("Falling back to User-Agent: " + user_agent)
                    resp = requests.get(self.uri, headers={"User-Agent": user_agent})
                    if resp.status_code == 200:
                        return resp.json()
                raise PyJWKClientError(f'Fail to fetch data from the url, status code: "{response.status_code}"')
