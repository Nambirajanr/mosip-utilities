import requests
from utils.app_logger import myprint
from utils.app_helper import get_timestamp, read_token, parse_response
from utils.app_json import dict_to_json
import config as conf
from utils.app_logger import info, error, debug

class MosipSession:
    def __init__(self, server, user, pwd, appid='resident', ssl_verify=True):
        self.server = server
        self.user = user
        self.pwd = pwd
        self.ssl_verify = conf.ssl_verify
        self.token = self.authGetToken(appid, self.user, self.pwd)

    def authGetToken(self, appid, username, pwd):
        myprint(f"authenticate api ({appid}) called")
        url = '%s/v1/authmanager/authenticate/clientidsecretkey' % self.server
        ts = get_timestamp()
        j = {
            "id": "mosip.io.clientId.pwd",
            "metadata": {},
            "version": "1.0",
            "requesttime": ts,
            "request": {
                "appId": appid,
                "clientId": username,
                "secretKey": pwd
            }
        }
        r = requests.post(url, json=j, verify=self.ssl_verify)
        resp = parse_response(r)
        debug("Response: "+ dict_to_json(resp))
        token = read_token(r)
        return token
    