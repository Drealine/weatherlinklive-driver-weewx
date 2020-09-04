#!/usr/bin/python3

DRIVER_NAME = "WLLDriver"
DRIVER_VERSION = "0.4"

import json
import requests
import socket
import urllib.request
import sys
import time
import weewx.drivers
import weewx.engine
import weewx.units
import collections
import hashlib
import hmac
import time
import datetime
import math
import copy

from socket import *
from datetime import datetime, timedelta

# Create socket for udp broadcast
socket_for_udp = socket(AF_INET, SOCK_DGRAM)
socket_for_udp.bind(('0.0.0.0', 22222))
socket_for_udp.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

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


class WLLDriverAPI():

    def __init__(self, api_parameters):

        # Define dict of sensor ID for Weatherlink.com
        self.dict_sensor_type = {'iss': {23, 24, 27, 28, 43, 44, 45, 46, 48, 49, 50,
                                         51, 76, 77, 78, 79, 80, 81, 82, 83},
                                 ('extraTemp1', 'extraTemp2', 'extraTemp3', 'extraTemp4', 'extraTemp5'): {55},
                                 ('extraHumid1', 'extraHumid2', 'extraHumid3', 'extraHumid4', 'extraHumid5'): {55},
                                 }

        # Define values for driver work
        self.api_parameters = api_parameters
        device_id = self.api_parameters['device_id']
        self.rain_previous_period = None
        self.udp_countdown = 0
        self.length_dict_device_id = None
        self.dict_device_id = dict((k, int(v)) for k, v in (e.split(':') for e in device_id.split('-')))
        self.length_dict_device_id = len(self.dict_device_id)
        self.check_health_time = False
        self.health_timestamp_archive = None
        self.list_iss = ['iss', 'iss+']
        self.list_anemometer = ['extraAnemometer']

        # Define URL for current conditions and udp broadcast
        self.url_current_conditions = "http://{}:{}/v1/current_conditions".format(self.api_parameters['hostname'],
                                                                                  self.api_parameters['port'])
        logdbg("URL of current_conditions : {}".format(self.url_current_conditions))
        self.url_realtime_broadcast = "http://{}:{}/v1/real_time?duration=3600".format(self.api_parameters['hostname'],
                                                                                       self.api_parameters['port'])
        logdbg("URL of realtime_broadcast : {}".format(self.url_realtime_broadcast))

        # Init time to request Health API
        if 'wl_archive_enable' in self.api_parameters and self.api_parameters['wl_archive_enable'] == 1:
            self.set_time_health_api()

    def round_minutes(self, timestamp, direction, resolution):

        # Function to get last time specify by up or down resolution
        now = datetime.fromtimestamp(timestamp)
        dt = now.replace(second=0, microsecond=0)
        new_minute = (dt.minute // resolution + (1 if direction == 'up' else 0)) * resolution
        result = dt + timedelta(minutes=new_minute - dt.minute)

        return int(datetime.timestamp(result))

    def request_json_data(self, url, request_timeout, type_of_request):

        try:
            http_session = requests.session()
            json_data = http_session.get(url, timeout=request_timeout)

            if json_data is not None:
                return json_data.json()

        except requests.Timeout as e:
            if type_of_request == 'HealthAPI':
                logdbg('Request timeout for HealthAPI, pass.')
                return
            else:
                raise weewx.WeeWxIOError('Request timeout from {} : {}'.format(type_of_request, e))
        except requests.RequestException as e:
            if type_of_request == 'HealthAPI':
                logdbg('Request exception for HealthAPI, pass.')
                return
            else:
                raise weewx.WeeWxIOError('Request exception from {} : {}'.format(type_of_request, e))

    def calculate_rain(self, rainFall_Daily, rainRate, rainSize):

        # Set values to None to prevent no declaration
        rain = None
        rain_multiplier = None

        # Check bucket size
        if rainSize is not None:
            if rainSize == 1:
                rain_multiplier = 0.01
            if rainSize == 2:
                rain_multiplier = 0.2
            if rainSize == 3:
                rain_multiplier = 0.1

        # Calculate rain
        if rainFall_Daily is not None and rain_multiplier is not None:
            if self.rain_previous_period is not None:
                if (rainFall_Daily - self.rain_previous_period) < 0:
                    logdbg('Not negative number. Set rain to 0. Essentially caused by reset midnight')
                    self.rain_previous_period = 0
                    rain = 0
                else:
                    rain = (rainFall_Daily - self.rain_previous_period) * rain_multiplier

                if rain is not None and rainSize is not None and rain > 0:
                    logdbg("Rain now : {}".format(rain))

                    if rainSize == 2:
                        rain = rain / 25.4
                    if rainSize == 3:
                        rain = rain / 2.54
        else:
            rain = None

        # Calculate rainRate
        if rainRate is not None and rain_multiplier is not None:
            if rainSize is not None and rainRate > 0:
                rainRate = rainRate * rain_multiplier
                logdbg("Rain Rate now : {}".format(rainRate))

                if rainSize == 2:
                    rainRate = rainRate / 25.4
                if rainSize == 3:
                    rainRate = rainRate / 2.54
        else:
            rainRate = None

        # Set rainFall_Daily to previous rain
        if rainFall_Daily is not None and rainFall_Daily >= 0:
            self.rain_previous_period = rainFall_Daily
            logdbg("Rainfall_Daily set after calculated : {}".format(self.rain_previous_period))

        return rain, rainRate

    def data_decode_health_wl(self, data, timestamp):

        # Function to decode health data from Weatherlink.com

        # Copy json data to new value
        data_wl = data
        # Set new dict
        dict_health = {}

        for sensor in self.dict_device_id:
            for index_json in range(0, len(data_wl['sensors']), 1):
                for sensor_type_id in self.dict_sensor_type[sensor]:
                    for s in data_wl['sensors']:
                        if s['sensor_type'] == sensor_type_id:
                            for q in data_wl['sensors'][index_json]['data']:
                                if 'tx_id' in q and q['tx_id'] == self.dict_device_id[sensor] \
                                        and q['ts'] == timestamp:
                                    if 'reception' in q:
                                        if sensor in self.list_iss:
                                            dict_health['rxCheckPercent'] = q['reception']

                    for s in data_wl['sensors']:
                        if s['sensor_type'] == 504:
                            for q in data_wl['sensors'][index_json]['data']:
                                if q['ts'] == timestamp:
                                    if 'battery_voltage' in q:
                                        tmp_battery_voltage = q['battery_voltage']
                                        if tmp_battery_voltage is not None:
                                            tmp_battery_voltage = tmp_battery_voltage / 1000
                                            dict_health['consBatteryVoltage'] = tmp_battery_voltage
                                    if 'input_voltage' in q:
                                        tmp_input_voltage = q['input_voltage']
                                        if tmp_input_voltage is not None:
                                            tmp_input_voltage = tmp_input_voltage / 1000
                                            dict_health['supplyVoltage'] = tmp_input_voltage

        if dict_health is not None and dict_health != {}:
            logdbg("Health Packet received from Weatherlink.com : {}".format(dict_health))
            yield dict_health

    def data_decode_wl(self, data, start_timestamp, end_timestamp):

        # Function to decode data from Weatherlink.com

        try:
            # Copy json data to new value
            data_wl = data

            # Set dict
            wl_packet = {'dateTime': None,
                         'usUnits': weewx.US,
                         'interval': self.api_parameters['wl_archive_interval'],
                         }
            extraTemp = {}
            extraHumid = {}

            # Set values to None
            rainSize = None

            # Calculate timestamp from start
            start_timestamp = int(start_timestamp + (60 * int(self.api_parameters['wl_archive_interval'])))

            while start_timestamp <= end_timestamp:
                logdbg("Request archive for timestamp : {}".format(start_timestamp))
                for sensor in self.dict_device_id:
                    check_key = str(sensor)
                    for index_json in range(0, len(data_wl['sensors']), 1):
                        for sensor_type_id in self.dict_sensor_type[sensor]:
                            for s in data_wl['sensors']:
                                if s['sensor_type'] == sensor_type_id:
                                    for q in data_wl['sensors'][index_json]['data']:
                                        if 'tx_id' in q and q['tx_id'] == self.dict_device_id[sensor] \
                                                and q['ts'] == start_timestamp:
                                            if 'temp_last' in q:
                                                if sensor in self.list_iss:
                                                    wl_packet['outTemp'] = q['temp_last']
                                                if 'extraTemp' in check_key:
                                                    extraTemp[sensor] = q['temp_last']

                                            if 'hum_last' in q:
                                                if sensor in self.list_iss:
                                                    wl_packet['outHumidity'] = q['hum_last']
                                                if 'extraHumid' in check_key:
                                                    extraHumid[sensor] = q['hum_last']

                                            if 'reception' in q:
                                                if sensor in self.list_iss:
                                                    wl_packet['rxCheckPercent'] = q['reception']

                                            if 'dew_point_last' in q:
                                                wl_packet['dewpoint'] = q['dew_point_last']
                                            if 'rain_size' in q:
                                                rainSize = q['rain_size']
                                            if 'heat_index_last' in q:
                                                wl_packet['heatindex'] = q['heat_index_last']
                                            if 'wind_chill_last' in q:
                                                wl_packet['windchill'] = q['wind_chill_last']
                                            if 'uv_index_avg' in q:
                                                wl_packet['UV'] = q['uv_index_avg']
                                            if 'solar_rad_avg' in q:
                                                wl_packet['radiation'] = q['solar_rad_avg']

                                            if sensor in self.list_iss or sensor in self.list_anemometer:
                                                if 'wind_speed_avg' in q:
                                                    wl_packet['windSpeed'] = q['wind_speed_avg']
                                                if 'wind_dir_of_prevail' in q:
                                                    wl_packet['windDir'] = q['wind_dir_of_prevail']
                                                if 'wind_speed_hi' in q:
                                                    wl_packet['windGust'] = q['wind_speed_hi']
                                                if 'wind_speed_hi_dir' in q:
                                                    wl_packet['windGustDir'] = q['wind_speed_hi_dir']

                                            if rainSize is not None and rainSize == 1:
                                                if 'rain_rate_hi_in' in q:
                                                    wl_packet['rainRate'] = q['rain_rate_hi_in']
                                                if 'rainfall_in' in q:
                                                    wl_packet['rain'] = q['rainfall_in']

                                            if rainSize is not None and rainSize == 2:
                                                if 'rain_rate_hi_mm' in q:
                                                    rainRate = q['rain_rate_hi_mm']
                                                    if rainRate is not None:
                                                        wl_packet['rainRate'] = rainRate / 25.4
                                                if 'rainfall_mm' in q:
                                                    rain = q['rainfall_mm']
                                                    if rain is not None:
                                                        wl_packet['rain'] = rain / 25.4

                                            # if rainSize == 3:

                                            # What about this value ? It is not implement on weatherlink.com ?

                            for s in data_wl['sensors']:
                                if s['sensor_type'] == 242:
                                    for q in data_wl['sensors'][index_json]['data']:
                                        if q['ts'] == start_timestamp:
                                            if 'bar_sea_level' in q:
                                                wl_packet['barometer'] = q['bar_sea_level']
                                            if 'bar_absolute' in q:
                                                wl_packet['pressure'] = q['bar_absolute']

                            for s in data_wl['sensors']:
                                if s['sensor_type'] == 243:
                                    for q in data_wl['sensors'][index_json]['data']:
                                        if q['ts'] == start_timestamp:
                                            if 'temp_in_last' in q:
                                                wl_packet['inTemp'] = q['temp_in_last']
                                            if 'hum_in_last' in q:
                                                wl_packet['inHumidity'] = q['hum_in_last']
                                            if 'dew_point_in' in q:
                                                wl_packet['inDewpoint'] = q['dew_point_in']

                            for s in data_wl['sensors']:
                                if s['sensor_type'] == 504:
                                    for q in data_wl['sensors'][index_json]['data']:
                                        if q['ts'] == start_timestamp:
                                            if 'battery_voltage' in q:
                                                tmp_battery_voltage = q['battery_voltage']
                                                if tmp_battery_voltage is not None:
                                                    tmp_battery_voltage = tmp_battery_voltage / 1000
                                                    wl_packet['consBatteryVoltage'] = tmp_battery_voltage
                                            if 'input_voltage' in q:
                                                tmp_input_voltage = q['input_voltage']
                                                if tmp_input_voltage is not None:
                                                    tmp_input_voltage = tmp_input_voltage / 1000
                                                    wl_packet['supplyVoltage'] = tmp_input_voltage

                wl_packet['dateTime'] = start_timestamp if start_timestamp is not None else None

                if len(self.dict_device_id) > 1:
                    if extraTemp is not None and extraTemp != {}:
                        wl_packet.update(extraTemp)

                    if extraHumid is not None and extraHumid != {}:
                        wl_packet.update(extraHumid)

                if wl_packet is not None and wl_packet['dateTime'] is not None:
                    logdbg("Packet received from Weatherlink.com : {}".format(wl_packet))
                    start_timestamp = int(start_timestamp + (60 * int(self.api_parameters['wl_archive_interval'])))
                    yield wl_packet

                else:
                    raise weewx.WeeWxIOError('No data present in Weatherlink.com packet but request is OK')

        except KeyError as e:
            raise weewx.WeeWxIOError('API Data from Weatherlink is invalid. Error is : {}'.format(e))
        except IndexError as e:
            raise weewx.WeeWxIOError('Structure type is not valid. Error is : {}'.format(e))

    def data_decode_wll(self, data, type_of_packet):

        # Function to decode data from WLL module
        try:
            # Set dict
            wll_packet = {'dateTime': None,
                          'usUnits': weewx.US,
                          }
            udp_wll_packet = {'dateTime': None,
                              'usUnits': weewx.US,
                              }
            extraTemp = {}
            extraHumid = {}
            add_current_rain = {}

            # Set values to None
            _packet = None
            rainFall_Daily = None
            rainRate = None
            rainSize = None

            for sensor in self.dict_device_id:
                check_key = str(sensor)
                if type_of_packet == 'current_conditions':
                    logdbg('Current conditions received : {}'.format(data))
                    if 'ts' in data['data']:
                        wll_packet['dateTime'] = data['data']['ts']

                    for s in data['data']['conditions']:
                        if s['data_structure_type'] == 1:
                            if s['txid'] == self.dict_device_id[sensor]:
                                if 'temp' in s:
                                    if sensor in self.list_iss:
                                        wll_packet['outTemp'] = s['temp']
                                    if 'extraTemp' in check_key:
                                        extraTemp[sensor] = s['temp']

                                if 'hum' in s:
                                    if sensor in self.list_iss:
                                        wll_packet['outHumidity'] = s['hum']
                                    if 'extraHumid' in check_key:
                                        extraHumid[sensor] = s['hum']

                                if sensor in self.list_iss:
                                    if 'dew_point' in s:
                                        wll_packet['dewpoint'] = s['dew_point']
                                    if 'heat_index' in s:
                                        wll_packet['heatindex'] = s['heat_index']
                                    if 'wind_chill' in s:
                                        wll_packet['windchill'] = s['wind_chill']
                                    if 'trans_battery_flag' in s:
                                        wll_packet['txBatteryStatus'] = s['trans_battery_flag']

                                if sensor in self.list_iss or sensor in self.list_anemometer:
                                    if 'wind_speed_last' in s:
                                        wll_packet['windSpeed'] = s['wind_speed_last']
                                    if 'wind_dir_last' in s:
                                        wll_packet['windDir'] = s['wind_dir_last']

                                    if self.api_parameters['wind_gust_2min_enable'] == 0:
                                        if 'wind_speed_hi_last_10_min' in s:
                                            wll_packet['windGust'] = s['wind_speed_hi_last_10_min']
                                        if 'wind_dir_at_hi_speed_last_10_min' in s:
                                            wll_packet['windGustDir'] = s['wind_dir_at_hi_speed_last_10_min']

                                    if self.api_parameters['wind_gust_2min_enable'] == 1:
                                        if 'wind_speed_hi_last_2_min' in s:
                                            wll_packet['windGust'] = s['wind_speed_hi_last_2_min']
                                        if 'wind_dir_at_hi_speed_last_2_min' in s:
                                            wll_packet['windGustDir'] = s['wind_dir_at_hi_speed_last_2_min']

                                if sensor in self.list_iss:
                                    if 'rain_rate_last' in s:
                                        rainRate = s['rain_rate_last']
                                    if 'rainfall_daily' in s:
                                        rainFall_Daily = s['rainfall_daily']
                                    if 'rain_size' in s:
                                        rainSize = s['rain_size']

                                if sensor in self.list_iss:
                                    if 'uv_index' in s:
                                        wll_packet['UV'] = s['uv_index']
                                    if 'solar_rad' in s:
                                        wll_packet['radiation'] = s['solar_rad']

                        # Next lines are not extra, so no need ID
                        if s['data_structure_type'] == 3:
                            if 'bar_sea_level' in s:
                                wll_packet['barometer'] = s['bar_sea_level']
                            if 'bar_absolute' in s:
                                wll_packet['pressure'] = s['bar_absolute']

                        if s['data_structure_type'] == 4:
                            if 'temp_in' in s:
                                wll_packet['inTemp'] = s['temp_in']
                            if 'hum_in' in s:
                                wll_packet['inHumidity'] = s['hum_in']
                            if 'dew_point_in' in s:
                                wll_packet['inDewpoint'] = s['dew_point_in']

                if type_of_packet == 'realtime_broadcast':
                    logdbg('Realtime broadcast received : {}'.format(data))
                    if 'ts' in data:
                        udp_wll_packet['dateTime'] = data['ts']

                    for s in data['conditions']:
                        if s['data_structure_type'] == 1:
                            if s['txid'] == self.dict_device_id[sensor]:
                                if self.api_parameters['realtime_enable'] == 1:
                                    if sensor in self.list_iss or sensor in self.list_anemometer:
                                        if 'wind_speed_last' in s:
                                            udp_wll_packet['windSpeed'] = s['wind_speed_last']
                                        if 'wind_dir_last' in s:
                                            udp_wll_packet['windDir'] = s['wind_dir_last']
                                        if 'wind_speed_hi_last_10_min' in s:
                                            udp_wll_packet['windGust'] = s['wind_speed_hi_last_10_min']
                                        if 'wind_dir_at_hi_speed_last_10_min' in s:
                                            udp_wll_packet['windGustDir'] = s['wind_dir_at_hi_speed_last_10_min']

                                    if sensor in self.list_iss:
                                        if 'rain_rate_last' in s:
                                            rainRate = s['rain_rate_last']
                                        if 'rainfall_daily' in s:
                                            rainFall_Daily = s['rainfall_daily']
                                        if 'rain_size' in s:
                                            rainSize = s['rain_size']
            # Get rain and rainRate
            logdbg("rainFall_Daily set : {}".format(rainFall_Daily))
            if self.rain_previous_period is not None:
                rain, rainRate = self.calculate_rain(rainFall_Daily, rainRate, rainSize)

                if rain is not None:
                    add_current_rain['rain'] = rain
                if rainRate is not None:
                    add_current_rain['rainRate'] = rainRate
            else:
                if rainFall_Daily is not None:
                    if rainFall_Daily >= 0:
                        self.rain_previous_period = rainFall_Daily
                        logdbg("rainFall_Daily set by WLLDriver : {}".format(self.rain_previous_period))

            # Get current_condition
            if type_of_packet == 'current_conditions':
                if add_current_rain is not None and add_current_rain != {}:
                    wll_packet.update(add_current_rain)

                if len(self.dict_device_id) > 1:
                    if extraTemp is not None and extraTemp != {}:
                        wll_packet.update(extraTemp)
                    if extraHumid is not None and extraHumid != {}:
                        wll_packet.update(extraHumid)

                if 'wl_archive_enable' in self.api_parameters and self.api_parameters['wl_archive_enable'] == 1:
                    for _health_packet in self.check_health_api(time.time()):
                        wll_packet.update(_health_packet)

                if wll_packet['dateTime'] is not None:
                    _packet = copy.copy(wll_packet)

                logdbg("Current conditions Weewx packet : {}".format(_packet))

            # Get realtime_broadcast
            if type_of_packet == 'realtime_broadcast':
                if add_current_rain is not None and add_current_rain != {}:
                    udp_wll_packet.update(add_current_rain)

                logdbg("Realtime broadcast Weewx packet : {}".format(udp_wll_packet))

                if udp_wll_packet['dateTime'] is not None:
                    _packet = copy.copy(udp_wll_packet)

            # Check datetime of packet to prevent no sync clock
            before_time = time.time() - 120
            after_time = time.time() + 120
            if _packet is not None and _packet['dateTime'] is not None and \
                    before_time <= _packet['dateTime'] <= after_time:
                logdbg("Final packet return to Weewx : {}".format(_packet))
                yield _packet
            else:
                raise weewx.WeeWxIOError('No data in WLL packet but request is OK')

        except KeyError as e:
            raise weewx.WeeWxIOError('API Data from WLL Module is invalid. Error is : {}'.format(e))
        except IndexError as e:
            raise weewx.WeeWxIOError('Structure type is not valid. Error is : {}'.format(e))

    def WLAPIv2(self, start_timestamp, end_timestamp):

        parameters = {
            "api-key": str(self.api_parameters['wl_apikey']),
            "api-secret": str(self.api_parameters['wl_apisecret']),
            "end-timestamp": str(end_timestamp),
            "start-timestamp": str(start_timestamp),
            "station-id": str(self.api_parameters['wl_stationid']),
            "t": int(time.time())
        }

        apiSecret = parameters["api-secret"]
        parameters.pop("api-secret", None)

        data = ""
        for key in parameters:
            data = data + key + str(parameters[key])

        apiSignature = hmac.new(
            apiSecret.encode('utf-8'),
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        url_wlapiv2 = "https://api.weatherlink.com/v2/historic/{}?api-key={}&t={}" \
                      "&start-timestamp={}&end-timestamp={}&api-signature={}"\
            .format(parameters["station-id"], parameters["api-key"], parameters["t"], parameters["start-timestamp"],
                    parameters["end-timestamp"], apiSignature)

        return url_wlapiv2

    def check_health_api(self, timestamp):

        now_time = int(timestamp - 120)  # Attempt 2min to archive new data from WL

        if self.health_timestamp_archive <= now_time:
            logdbg("Request health conditions into current_conditions for "
                   "timestamp : {}".format(self.health_timestamp_archive))

            for _health_packet in self.request_health_wl(self.health_timestamp_archive -
                                                         (self.api_parameters['wl_archive_interval'] * 60),
                                                         self.health_timestamp_archive):
                logdbg("Health conditions packet received : {}".format(_health_packet))
                if _health_packet is not None:
                    yield _health_packet

            # Set values to False and None to prevent block code on current_conditions same that URL is None
            self.check_health_time = False
            self.health_timestamp_archive = None

        self.set_time_health_api()

    def set_time_health_api(self):

        # Set time of HealthAPI for future request
        if not self.check_health_time:
            current_time = time.time()
            self.health_timestamp_archive = self.round_minutes(current_time, 'up', 15)
            self.check_health_time = True
            logdbg("Set future time request health API to {}".format(self.health_timestamp_archive))

    def request_health_wl(self, start_timestamp, end_timestamp):

        # Function to request health archive from Weatherlink.com
        url_apiv2_wl = self.WLAPIv2(start_timestamp, end_timestamp)
        logdbg("URL API Weatherlink : {} ".format(url_apiv2_wl))
        data_wl = self.request_json_data(url_apiv2_wl, self.api_parameters['time_out'], 'HealthAPI')

        for _packet in self.data_decode_health_wl(data_wl, end_timestamp):
            if _packet is not None:
                yield _packet

    def request_wl(self, start_timestamp, end_timestamp):

        # Function to request archive from Weatherlink.com
        index_start_timestamp = 0
        index_end_timestamp = 1
        dict_timestamp = {}
        index_timestamp = 0

        start_timestamp = self.round_minutes(start_timestamp, 'down', self.api_parameters['wl_archive_interval'])
        result_timestamp = end_timestamp - start_timestamp

        # Due to limit size on Weatherlink, if result timestamp is more thant 24h, split the request
        if result_timestamp >= 86400:
            while start_timestamp + 86400 < end_timestamp and index_timestamp <= 300:
                dict_timestamp[start_timestamp, start_timestamp + 86400] = index_timestamp
                start_timestamp = start_timestamp + 86400
                index_timestamp += 1

            dict_timestamp[start_timestamp, end_timestamp] = index_timestamp
        else:
            dict_timestamp[start_timestamp, end_timestamp] = 0

        if dict_timestamp != {}:
            for archive_interval in dict_timestamp:
                url_apiv2_wl = self.WLAPIv2(archive_interval[index_start_timestamp],
                                            archive_interval[index_end_timestamp])
                logdbg("URL API Weatherlink : {} ".format(url_apiv2_wl))
                data_wl = self.request_json_data(url_apiv2_wl, self.api_parameters['time_out'], 'Weatherlink.com')

                for _packet in self.data_decode_wl(data_wl, archive_interval[index_start_timestamp],
                                                   archive_interval[index_end_timestamp]):
                    if _packet is not None:
                        yield _packet

    def request_wll(self, type_of_packet):

        if type_of_packet == 'current_conditions':
            wll_packet = self.request_json_data(self.url_current_conditions, self.api_parameters['time_out'],
                                                type_of_packet)

            for _packet in self.data_decode_wll(wll_packet, type_of_packet):
                if _packet is not None:
                    yield _packet

        if type_of_packet == 'realtime_broadcast':
            data_broadcast = self.get_realtime_broadcast()

            if data_broadcast is not None:
                for _packet in self.data_decode_wll(data_broadcast, type_of_packet):
                    if _packet is not None:
                        yield _packet

    def request_realtime_broadcast(self):

        if self.udp_countdown - self.api_parameters['poll_interval'] < time.time():
            rb = self.request_json_data(self.url_realtime_broadcast, self.api_parameters['time_out'],
                                        'Realtime_broadcast')

            if rb['data'] is not None:
                self.udp_countdown = time.time() + rb['data']['duration']
                return

    def get_realtime_broadcast(self):

        if self.udp_countdown - self.api_parameters['poll_interval'] > time.time():
            try:
                data, where_from = socket_for_udp.recvfrom(2048)
                realtime_data = json.loads(data.decode("utf-8"))

                if realtime_data is not None:
                    return realtime_data

            except OSError:
                logdbg("Failure to get realtime data")


def loader(config_dict, engine):
    # Define the driver

    return WLLDriver(**config_dict[DRIVER_NAME], **config_dict)


class WLLDriver(weewx.drivers.AbstractDevice):

    def __init__(self, **stn_dict):

        # Define description of driver
        self.vendor = "Davis"
        self.product = "WeatherLinkLive"
        self.model = "WLLDriver"

        # Setting require parameters to start WLLDriver
        self.api_parameters = {'max_tries': int(stn_dict.get('max_tries', 5)),
                               'time_out': int(stn_dict.get('time_out', 10)),
                               'retry_wait': int(stn_dict.get('retry_wait', 10)),
                               'poll_interval': int(stn_dict.get('poll_interval', 5)),
                               'realtime_enable': int(stn_dict.get('realtime_enable', 0)),
                               'wind_gust_2min_enable': int(stn_dict.get('wind_gust_2min_enable', 0)),
                               'hostname': (stn_dict.get('hostname', None)),
                               'port': (stn_dict.get('port', "80")),
                               'device_id': (stn_dict.get('device_id', str("iss:1"))),
                               'wl_archive_enable': int(stn_dict.get('wl_archive_enable', 1))}

        # Verify conditions of require parameters before start the driver
        if self.api_parameters['max_tries'] >= 200:
            raise weewx.ViolatedPrecondition("Max tries can't be more than 200 tries")
        if self.api_parameters['time_out'] >= 15:
            raise weewx.ViolatedPrecondition("Timeout can't be more than 15 seconds for better use")
        if self.api_parameters['retry_wait'] < self.api_parameters['poll_interval']:
            raise weewx.ViolatedPrecondition("Retry wait must be more than poll interval")
        if self.api_parameters['realtime_enable'] == 1 and self.api_parameters['wind_gust_2min_enable'] == 1:
            raise weewx.ViolatedPrecondition("Wind gust 2min can't be set while realtime is enable")
        if self.api_parameters['hostname'] is None: raise weewx.ViolatedPrecondition("Hostname or IP must be set")

        for key in self.api_parameters:
            if isinstance(self.api_parameters[key], int):
                if self.api_parameters[key] < 0:
                    raise weewx.ViolatedPrecondition("{} can't be a negative number".format(key))

        # Check if the user set wl_retrieve_enable to 1
        if self.api_parameters['wl_archive_enable'] == 1:
            self.wl_archive_parameters = {'wl_apisecret': (stn_dict.get('wl_apisecret', None)),
                                          'wl_stationid': (stn_dict.get('wl_stationid', None)),
                                          'wl_archive_interval': int(stn_dict.get('wl_archive_interval', 15)),
                                          'wl_apikey': (stn_dict.get('wl_apikey', None))}
            for key in self.wl_archive_parameters:
                if self.wl_archive_parameters[key] is None:
                    raise weewx.ViolatedPrecondition("{} must be set".format(key))

            if len(self.wl_archive_parameters['wl_apisecret']) not in [32]:
                raise weewx.ViolatedPrecondition("wl_apisecret must be 32 characters long")
            if len(self.wl_archive_parameters['wl_apikey']) not in [32]:
                raise weewx.ViolatedPrecondition("wl_apikey must be 32 characters long")

            if self.wl_archive_parameters['wl_archive_interval'] not in [1, 5, 15]:
                raise weewx.ViolatedPrecondition("Wrong archive interval Weatherlink.com. It must be 1, 5 or 15min.")

            # Add parameters to the current api_parameters
            self.api_parameters.update(self.wl_archive_parameters)

        # Define number of try to 1
        self.ntries = 1

        # Define WLLDriverAPI
        self.WLLDriverAPI = WLLDriverAPI(self.api_parameters)

        # Show description at startup of Weewx
        loginf("Driver name is %s" % DRIVER_NAME)
        loginf("Driver version is %s" % DRIVER_VERSION)
        loginf("Polling interval set to %s" % self.api_parameters['poll_interval'])

    # Function below are defined for Weewx engine :
    @property
    def hardware_name(self):

        # Define hardware name
        return self.model

    def genStartupRecords(self, good_stamp):

        if 'wl_archive_enable' in self.api_parameters and self.api_parameters['wl_archive_enable'] == 1:
            # Generate values since good stamp in Weewx database
            while self.ntries <= 5:
                try:
                    now_timestamp_wl = self.WLLDriverAPI.round_minutes(time.time(), 'down',
                                                                       self.api_parameters['wl_archive_interval'])
                    # Add 60 seconds timestamp to wait the WLL archive new data
                    if good_stamp is not None and (good_stamp + 60 < now_timestamp_wl):
                        for _packet_wl in self.WLLDriverAPI.request_wl(good_stamp, now_timestamp_wl):
                            yield _packet_wl
                            good_stamp = time.time() + 0.5
                            self.ntries = 1
                    else:
                        return

                except weewx.WeeWxIOError as e:
                    logerr("Failed attempt %d of %d to get loop data in genStartupRecords: %s" %
                           (self.ntries, 5, e))
                    self.ntries += 1
                    time.sleep(self.api_parameters['retry_wait'])
            else:
                return
        else:
            return

    def genLoopPackets(self):

        # Make loop packet specify by user by poll interval
        while self.ntries < self.api_parameters['max_tries']:
            try:
                for _packet_wll in self.WLLDriverAPI.request_wll('current_conditions'):
                    yield _packet_wll
                    self.ntries = 1

                if self.api_parameters['realtime_enable'] == 0:
                    if self.api_parameters['poll_interval']:
                        time.sleep(self.api_parameters['poll_interval'])

                if self.api_parameters['realtime_enable'] == 1:
                    timeout_udp_broadcast = time.time() + self.api_parameters['poll_interval']

                    self.WLLDriverAPI.request_realtime_broadcast()

                    while time.time() < timeout_udp_broadcast:
                        for _realtime_packet in self.WLLDriverAPI.request_wll('realtime_broadcast'):
                            yield _realtime_packet
                            self.ntries = 1

            except weewx.WeeWxIOError as e:
                logerr("Failed attempt %d of %d to get loop data in genLoopPackets: %s" %
                       (self.ntries, self.api_parameters['max_tries'], e))
                self.ntries += 1
                time.sleep(self.api_parameters['retry_wait'])
        else:
            msg = "Max retries (%d) exceeded for LOOP data" % self.api_parameters['max_tries']
            logerr(msg)
            raise weewx.RetriesExceeded(msg)


# ==============================================================================
# Main program
#
# To test this driver, do the following:
#   PYTHONPATH="Path of your 'bin' folder specific of your Weewx installation" python3 /home/weewx/bin/user/WLLDriver.py
#
# ==============================================================================

if __name__ == "__main__":
    usage = """%prog [options] [--help]"""


    def main():
        try:
            import logging
            import weeutil.logger
            log = logging.getLogger(__name__)
            weeutil.logger.setup('WLLDriver', {})
        except ImportError:
            import syslog
            syslog.openlog('WLLDriver', syslog.LOG_PID | syslog.LOG_CONS)

        import optparse
        parser = optparse.OptionParser(usage=usage)
        parser.add_option('--test-driver', dest='td', action='store_true',
                          help='test the driver')
        (options, args) = parser.parse_args()

        if options.td:
            test_driver()


    def test_driver():
        import weeutil.weeutil
        driver = WLLDriver()
        print("testing driver")
        for pkt in driver.genLoopPackets():
            print((weeutil.weeutil.timestamp_to_string(pkt['dateTime']), pkt))


    main()
