import weewx
import json
import requests
import time
import weewx.units
import socket
from datetime import datetime, timedelta
from weewx.engine import StdService

weewx.units.obs_group_dict['windSpeedNetatmo'] = 'group_speed'
weewx.units.obs_group_dict['windGustNetatmo'] = 'group_speed'
weewx.units.obs_group_dict['rainNetatmo'] = 'group_rain'
weewx.units.obs_group_dict['windGustDirNetatmo'] = 'group_direction'
weewx.units.obs_group_dict['windDirNetatmo'] = 'group_direction'
weewx.units.obs_group_dict['barometerNetatmo'] = 'group_pressure'
weewx.units.obs_group_dict['outTempNetatmo'] = 'group_temperature'
weewx.units.obs_group_dict['outHumidityNetatmo'] = 'group_percent'
weewx.units.obs_group_dict['datetimeNetatmo'] = 'group_time'

try:
    import weeutil.logger
    import logging

    log = logging.getLogger(__name__)


    def logdbg(msg):
        log.debug(msg)


    def loginf(msg):
        log.info(msg)


    def logerr(msg):
        log.error(msg)

except ImportError:
    import syslog


    def logmsg(level, msg):
        syslog.syslog(level, 'WLLDriver: %s:' % msg)


    def logdbg(msg):
        logmsg(syslog.LOG_DEBUG, msg)


    def loginf(msg):
        logmsg(syslog.LOG_INFO, msg)


    def logerr(msg):
        logmsg(syslog.LOG_ERR, msg)


class NetatmoAPI():

    def __init__(self, clientId,
                 clientSecret,
                 username,
                 password,
                 mac_address,
                 scope="read_station"):

        postParams = {
            "grant_type": "password",
            "client_id": clientId,
            "client_secret": clientSecret,
            "username": username,
            "password": password,
            "scope": scope
        }

        self.netatmo_url_token = "https://api.netatmo.com/oauth2/token"
        self.netatmo_current_conditions = "https://api.netatmo.com/api/getstationsdata"

        self.current_datatime = None
        self.current_rain = None
        self.mac_address = mac_address

        for resp in self.postRequest(self.netatmo_url_token, postParams, type_of_request='first_token'):
            try:
                if not resp:
                    raise weewx.ViolatedPrecondition("Authentication request rejected")
                else:
                    self._clientId = clientId
                    self._clientSecret = clientSecret
                    self._accessToken = resp['access_token']
                    self.refreshToken = resp['refresh_token']
                    self._scope = resp['scope']
                    self.expiration = int(resp['expire_in'] + time.time())

            except KeyError as e:
                logerr("API data from Netatmo is not valid. Authentication request rejected")
            except IndexError as e:
                logerr("Structure type of Netatmo is not valid. Authentication request rejected")

        self.last_midnight = self.get_last_midnight()
        logdbg("Last midnight set is : {}".format(self.last_midnight))

    @staticmethod
    def get_last_midnight():

        midnight = datetime.combine(datetime.today(), datetime.min.time())
        next_midnight = datetime.timestamp(midnight + timedelta(days=1))
        return next_midnight

    @property
    def accessToken(self):

        try:
            if self.expiration < time.time():  # Token should be renewed
                postParams = {
                    "grant_type": "refresh_token",
                    "refresh_token": self.refreshToken,
                    "client_id": self._clientId,
                    "client_secret": self._clientSecret
                }
                for resp in self.postRequest(self.netatmo_url_token, postParams):
                    if resp:
                        self._accessToken = resp['access_token']
                        self.refreshToken = resp['refresh_token']
                        self.expiration = int(resp['expire_in'] + time.time())
                        return self._accessToken
            else:
                return self._accessToken

        except KeyError as e:
            logerr('API Data from Netatmo is invalid. Error is : {}'.format(e))
        except IndexError as e:
            logerr('Structure type of Netatmo is not valid. Error is : {}'.format(e))

    @staticmethod
    def postRequest(url, params, timeout=2, type_of_request=None):

        if params:
            try:
                resp = requests.post(url, data=params, timeout=timeout) if params else \
                    requests.post(url, timeout=timeout)

                resp.raise_for_status()
                if resp is not None:
                    yield resp.json()

            except requests.HTTPError as e:
                if type_of_request == 'first_token':
                    raise weewx.ViolatedPrecondition("Error while request HTTP token. Error is : {}".format(e))
                else:
                    logerr("Error while request URL [{}]. Error is : {}".format
                           (url, e))
            except requests.Timeout as e:
                if type_of_request == 'first_token':
                    raise weewx.ViolatedPrecondition("Error while request HTTP token. Error is : {}".format(e))
                else:
                    logerr("Error while request URL [{}]. Error is : {}".format
                           (url, e))
            except requests.RequestException as e:
                if type_of_request == 'first_token':
                    raise weewx.ViolatedPrecondition("Error while request HTTP token. Error is : {}".format(e))
                else:
                    logerr("Error while request URL [{}]. Error is : {}".format
                           (url, e))

    def calculate_rain(self, dt, rainfall_daily):

        if self.last_midnight < dt:
            loginf('Reset rainfall_Daily at midnight')
            self.current_rain = 0
            self.last_midnight = self.get_last_midnight()
            logdbg("Last midnight set is : {}".format(self.last_midnight))

        if (rainfall_daily - self.current_rain) < 0:
            logerr("rain can't be a negative number. Skip this and set rain to 0")
            rain = 0
        else:
            rain = rainfall_daily - self.current_rain
            self.current_rain = rainfall_daily
            logdbg("Rainfall_Daily set after calculated : {}".format(self.current_rain))

        return rain

    def decode_current_conditions(self):

        pk_netatmo = {}
        auth_token = self.accessToken
        postParams = {
            "access_token": auth_token
        }

        try:
            for rp in self.postRequest(self.netatmo_current_conditions, postParams):
                for int_modules in rp['body']['devices']:
                    if self.mac_address in int_modules['_id']:
                        pk_netatmo['barometerNetatmo'] = int_modules['dashboard_data']['Pressure']
                        pk_netatmo['dateTimeNetatmo'] = int_modules['last_status_store']

                        for ext_modules in int_modules['modules']:
                            if 'Temperature' in ext_modules['data_type'] and \
                                    'Humidity' in ext_modules['data_type']:
                                pk_netatmo['outHumidityNetatmo'] = ext_modules['dashboard_data']['Humidity']
                                pk_netatmo['outTempNetatmo'] = ext_modules['dashboard_data']['Temperature']

                            if 'Rain' in ext_modules['data_type']:
                                if 'sum_rain_24' in ext_modules['dashboard_data']:
                                    # Check this key to prevent problem at midnight
                                    if self.current_rain is None:
                                        self.current_rain = ext_modules['dashboard_data']['sum_rain_24']
                                        logdbg("Rainfall_Daily set : {}".format(self.current_rain))
                                    else:
                                        pk_netatmo['rainNetatmo'] = \
                                            self.calculate_rain(pk_netatmo['dateTimeNetatmo'],
                                                                ext_modules['dashboard_data']['sum_rain_24'])

                            if 'Wind' in ext_modules['data_type']:
                                pk_netatmo['windSpeedNetatmo'] = ext_modules['dashboard_data']['WindStrength']
                                pk_netatmo['windDirNetatmo'] = ext_modules['dashboard_data']['WindAngle']
                                pk_netatmo['windGustNetatmo'] = ext_modules['dashboard_data']['GustStrength']
                                pk_netatmo['windGustDirNetatmo'] = ext_modules['dashboard_data']['GustAngle']

            if pk_netatmo != {} and pk_netatmo is not None:
                if self.current_datatime is None:
                    self.current_datatime = pk_netatmo['dateTimeNetatmo']
                    loginf("Current last seen of Netatmo is {}. Wait next archive from Netatmo to sync "
                           "with Weewx database".format(self.current_datatime))
                else:
                    if self.current_datatime != pk_netatmo['dateTimeNetatmo']:
                        self.current_datatime = pk_netatmo['dateTimeNetatmo']
                        loginf("Last seen Netatmo : {}".format(self.current_datatime))
                        logdbg("Weewx archive packet from Netatmo : {}".format(pk_netatmo))
                        yield pk_netatmo
                    else:
                        loginf("No new archive from Netatmo. Last seen : {}".format(self.current_datatime))

        except KeyError as e:
            logerr('API Data from Netatmo is invalid. Error is : {}'.format(e))
        except IndexError as e:
            logerr('Structure type of Netatmo is not valid. Error is : {}'.format(e))


class AddNetatmo(StdService):

    def __init__(self, engine, config_dict):

        # Initialize my superclass first:
        super(AddNetatmo, self).__init__(engine, config_dict)

        self.bind(weewx.NEW_ARCHIVE_RECORD, self.new_archive_record)

        self.netatmo_enable = int(config_dict['WLLDriver'].get('netatmo_enable', 0))

        if self.netatmo_enable == 1:
            self.netatmo_parameters = {'client_id': str(config_dict['WLLDriver'].get('client_id', None)),
                                       'client_secret': str(config_dict['WLLDriver'].get('client_secret', None)),
                                       'username': str(config_dict['WLLDriver'].get('username', None)),
                                       'password': str(config_dict['WLLDriver'].get('password', None)),
                                       'mac_address': str(config_dict['WLLDriver'].get('mac_address', None))}
            for key in self.netatmo_parameters:
                if self.netatmo_parameters[key] is None:
                    raise weewx.ViolatedPrecondition("{} must be set".format(key))

            self.NetatmoAPI = NetatmoAPI(clientId=self.netatmo_parameters['client_id'],
                                         clientSecret=self.netatmo_parameters['client_secret'],
                                         username=self.netatmo_parameters['username'],
                                         password=self.netatmo_parameters['password'],)

    def new_archive_record(self, event):

        if self.netatmo_enable == 1:
            for _netatmo_pk in self.NetatmoAPI.decode_current_conditions():
                wind_speed_vt = weewx.units.ValueTuple(_netatmo_pk['windSpeedNetatmo'],
                                                       'km_per_hour', 'group_speed')
                wind_speed_converted_vt = weewx.units.convertStd(wind_speed_vt, event.record['usUnits'])
                event.record['windSpeedNetatmo'] = wind_speed_converted_vt.value

                wind_gust_vt = weewx.units.ValueTuple(_netatmo_pk['windGustNetatmo'],
                                                       'km_per_hour', 'group_speed')
                wind_gust_converted_vt = weewx.units.convertStd(wind_gust_vt, event.record['usUnits'])
                event.record['windGustNetatmo'] = wind_gust_converted_vt.value

                barometer_vt = weewx.units.ValueTuple(_netatmo_pk['barometerNetatmo'],
                                                       'hPa', 'group_pressure')
                barometer_converted_vt = weewx.units.convertStd(barometer_vt, event.record['usUnits'])
                event.record['barometerNetatmo'] = barometer_converted_vt.value

                rain_vt = weewx.units.ValueTuple(_netatmo_pk['rainNetatmo'],
                                                      'mm', 'group_rain')
                rain_converted_vt = weewx.units.convertStd(rain_vt, event.record['usUnits'])
                event.record['rainNetatmo'] = rain_converted_vt.value

                outtemp_vt = weewx.units.ValueTuple(_netatmo_pk['outTempNetatmo'],
                                                 'degree_C', 'group_temperature')
                outtemp_converted_vt = weewx.units.convertStd(outtemp_vt, event.record['usUnits'])
                event.record['outTempNetatmo'] = outtemp_converted_vt.value

                event.record['windGustDirNetatmo'] = _netatmo_pk['windGustDirNetatmo']
                event.record['windDirNetatmo'] = _netatmo_pk['windDirNetatmo']
                event.record['dateTimeNetatmo'] = _netatmo_pk['dateTimeNetatmo']
                event.record['outHumidityNetatmo'] = _netatmo_pk['outHumidityNetatmo']
        else:
            return
