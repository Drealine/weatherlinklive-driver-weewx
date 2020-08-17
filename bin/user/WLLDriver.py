#!/usr/bin/python3

DRIVER_NAME = "WLLDriver"
DRIVER_VERSION = "0.2"

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

# Create socket for udp broadcast

comsocket = socket(AF_INET, SOCK_DGRAM)
comsocket.bind(('0.0.0.0', 22222))
comsocket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

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

        # Define sensor ID for Weatherlink.com

        self.dict_sensor_type = {'iss': {46, 48, 43},
                                 'extraTemp': {55},
                                 'extraHumid': {55},
                                 }

        self.matches_sensor_type = ('iss', 'iss+', 'extraTemp', 'extraHumid')

        # Define values for driver work

        self.api_parameters = api_parameters
        # comsocket.settimeout(self.api_parameters['time_out'])
        device_id = self.api_parameters['device_id']
        self.rain_previous_period = None
        self.udp_countdown = 0
        self.length_dict_device_id = None
        self.dict_device_id = dict((int(k), v) for k, v in (e.split(':') for e in device_id.split('-')))
        self.length_dict_device_id = len(self.dict_device_id)

        # Define URL for current conditions and udp broadcast

        self.url_current_conditions = "http://{}/v1/current_conditions".format(self.api_parameters['hostname'])
        self.url_realtime_broadcast = "http://{}/v1/real_time?duration=3600".format(self.api_parameters['hostname'])

        # Define schema packet for WLL and Weatherlink.com

        self.schema_wl_packet = {'dateTime': None,
                                 'usUnits': weewx.US,
                                 'interval': self.api_parameters['wl_archive_interval'],
                                 }

        self.schema_wll_packet = {'dateTime': None,
                                  'usUnits': weewx.US,
                                  }

        self.schema_udp_wll_packet = {'dateTime': None,
                                      'usUnits': weewx.US,
                                      }

    def get_timestamp_wl_archive(self):

        # Get the last timestamp of Weatherlink archive interval set in conf driver

        timestamp_wl_archive = int(
            math.floor((time.time() - 60) / (self.api_parameters['wl_archive_interval'] * 60)) *
            (self.api_parameters['wl_archive_interval'] * 60))

        return timestamp_wl_archive

    def get_timestamp_by_time(self, timestamp):

        # Get timestamp from specific time of Weatherlink archive interval set in conf driver

        timestamp_wl_archive = int(
            math.floor((timestamp - 60) / (self.api_parameters['wl_archive_interval'] * 60)) *
            (self.api_parameters['wl_archive_interval'] * 60))

        return timestamp_wl_archive

    def request_json_data(self, url, request_timeout, type_of_request):

        json_data = None

        try:
            http_session = requests.session()
            json_data = http_session.get(url, timeout=request_timeout)

            if json_data is not None:
                return json_data.json()

        except requests.Timeout as error:
            raise weewx.WeeWxIOError('Request timeout from {} : {}'.format(type_of_request, error))

        except requests.RequestException as error:
            raise weewx.WeeWxIOError('Request exception from {} : {}'.format(type_of_request, error))

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
                    logdbg(
                        'Not a negative number, so set previous rain and rain to 0. It might cause by reset midnight')
                    self.rain_previous_period = 0
                    rain = 0
                else:
                    rain = (rainFall_Daily - self.rain_previous_period) * rain_multiplier

                if rain > 0 and rain is not None and rainSize is not None:
                    logdbg("Rain now : {}".format(rain))

                    if rainSize == 2:
                        rain = rain / 25.4

                    if rainSize == 3:
                        rain = rain / 2.54
        else:
            rain = None

        # Calculate rainRate
        if rainRate is not None and rain_multiplier is not None:
            if rainRate > 0 and rainSize is not None:
                rainRate = rainRate * rain_multiplier
                logdbg("Rain Rate now : {}".format(rainRate))

                if rainSize == 2:
                    rainRate = rainRate / 25.4

                if rainSize == 3:
                    rainRate = rainRate / 2.54
        else:
            rainRate = None

        if rainFall_Daily is not None and rainFall_Daily >= 0:
            self.rain_previous_period = rainFall_Daily
            logdbg("Rainfall_Daily set after calculated : {}".format(self.rain_previous_period))

        return rain, rainRate

    def data_decode_wl(self, data, start_timestamp, end_timestamp):

        # Function to decode data from Weatherlink.com

        try:
            # Copie json data to new value
            data_wl = data

            # Set dict
            extraTemp = {}
            extraHumid = {}

            # Set values to None
            rainSize = None

            # Calculate timestamp from start
            start_timestamp = int(start_timestamp + (60 * int(self.api_parameters['wl_archive_interval'])))

            while start_timestamp <= end_timestamp:
                logdbg("Request archive for timestamp : {}".format(start_timestamp))
                wl_packet = copy.copy(self.schema_wl_packet)

                for nmb_device_id in range(1, len(self.dict_device_id) + 1, 1):
                    for index_json in range(0, len(data_wl['sensors']), 1):
                        for device_id, device in self.dict_device_id.items():
                            temp_dict_device_id = self.dict_device_id[device_id]
                            temp_dict_device_id = ''.join([i for i in temp_dict_device_id if not i.isdigit()])

                            for sensor_type_id in self.dict_sensor_type[temp_dict_device_id]:
                                for s in data_wl['sensors']:
                                    if s['sensor_type'] == sensor_type_id:
                                        for s in data_wl['sensors'][index_json]['data']:
                                            if 'tx_id' in s and s['tx_id'] == device_id and s['ts'] == start_timestamp:
                                                if 'temp_last' in s:
                                                    if self.dict_device_id[device_id] == 'iss' or \
                                                            self.dict_device_id[device_id] == 'iss+':
                                                        wl_packet['outTemp'] = s['temp_last']

                                                    if self.dict_device_id[device_id] in 'extraTemp{}'.format(
                                                            nmb_device_id):
                                                        extraTemp[
                                                            'extraTemp{}'.format(nmb_device_id)] = \
                                                            s['temp_last']

                                                if 'hum_last' in s:
                                                    if self.dict_device_id[device_id] == 'iss' or \
                                                            self.dict_device_id[device_id] == 'iss+':
                                                        wl_packet['outHumidity'] = s['hum_last']

                                                    if self.dict_device_id[device_id] == 'extraHumid{}'.format(
                                                            nmb_device_id):
                                                        extraHumid[
                                                            'extraHumid{}'.format(
                                                                nmb_device_id)] = s['hum_last']
                                                if 'dew_point_last' in s:
                                                    wl_packet['dewpoint'] = s['dew_point_last']
                                                if 'rain_size' in s:
                                                    rainSize = s['rain_size']
                                                if 'heat_index_last' in s:
                                                    wl_packet['heatindex'] = s['heat_index_last']
                                                if 'wind_chill_last' in s:
                                                    wl_packet['windchill'] = s['wind_chill_last']
                                                if 'wind_speed_avg' in s:
                                                    wl_packet['windSpeed'] = s['wind_speed_avg']
                                                if 'wind_dir_of_prevail' in s:
                                                    wl_packet['windDir'] = s['wind_dir_of_prevail']
                                                if 'wind_speed_hi' in s:
                                                    wl_packet['windGust'] = s['wind_speed_hi']
                                                if 'wind_speed_hi_dir' in s:
                                                    wl_packet['windGustDir'] = s['wind_speed_hi_dir']
                                                if 'uv_index_avg' in s:
                                                    wl_packet['UV'] = s['uv_index_avg']
                                                if 'solar_rad_avg' in s:
                                                    wl_packet['radiation'] = s['solar_rad_avg']

                                                if rainSize == 1:
                                                    if 'rain_rate_hi_in' in s:
                                                        wl_packet['rainRate'] = s['rain_rate_hi_in']

                                                    if 'rainfall_in' in s:
                                                        wl_packet['rain'] = s['rainfall_in']

                                                if rainSize == 2:
                                                    if 'rain_rate_hi_mm' in s:
                                                        rainRate = s['rain_rate_hi_mm']

                                                        if rainRate is not None:
                                                            wl_packet['rainRate'] = rainRate / 25.4

                                                    if 'rainfall_mm' in s:
                                                        rain = s['rainfall_mm']

                                                        if rain is not None:
                                                            wl_packet['rain'] = rain / 25.4

                                                # if rainSize == 3:

                                                # What about this value ? Is not implement on weatherlink.com ?

                                for s in data_wl['sensors']:
                                    if s['sensor_type'] == 242:
                                        for s in data_wl['sensors'][index_json]['data']:
                                            if s['ts'] == start_timestamp:
                                                if 'bar_sea_level' in s:
                                                    wl_packet['barometer'] = s['bar_sea_level']
                                                if 'bar_absolute' in s:
                                                    wl_packet['pressure'] = s['bar_absolute']

                                for s in data_wl['sensors']:
                                    if s['sensor_type'] == 243:
                                        for s in data_wl['sensors'][index_json]['data']:
                                            if s['ts'] == start_timestamp:
                                                if 'temp_in_last' in s:
                                                    wl_packet['inTemp'] = s['temp_in_last']
                                                if 'hum_in_last' in s:
                                                    wl_packet['inHumidity'] = s['hum_in_last']
                                                if 'dew_point_in' in s:
                                                    wl_packet['inDewpoint'] = s['dew_point_in']

                wl_packet['dateTime'] = start_timestamp

                if len(self.dict_device_id) > 1:
                    if extraTemp is not None:
                        wl_packet.update(extraTemp)

                    if extraHumid is not None:
                        wl_packet.update(extraHumid)

                if wl_packet is not None:
                    logdbg("Packet received from Weatherlink.com : {}".format(wl_packet))
                    start_timestamp = int(start_timestamp + (60 * int(self.api_parameters['wl_archive_interval'])))
                    yield wl_packet

                else:
                    raise weewx.WeeWxIOError('No data present in Weatherlink.com packet but request is OK')

        except KeyError as error:
            raise weewx.WeeWxIOError('API Data from Weatherlink is invalid. Error is : {}'.format(error))
        except IndexError as error:
            raise weewx.WeeWxIOError('Structure type is not valid. Error is : {}'.format(error))

        # Keep this line for futur use
        '''if self.poll_interval: 
            time.sleep(self.poll_interval)'''

    def data_decode_wll(self, data, type_of_packet):

        # Function to decode data from WLL module

        try:
            # global rainFall_Daily

            # Set dict
            extraTemp = {}
            extraHumid = {}

            # Set values to None
            add_current_rain = None
            _packet = None
            rainFall_Daily = None
            rainRate = None
            rainSize = None

            # Copy schema to new value
            wll_packet = copy.copy(self.schema_wll_packet)
            udp_wll_packet = copy.copy(self.schema_udp_wll_packet)

            for device_id, device in self.dict_device_id.items():
                for nmb_device_id in range(1, len(self.dict_device_id) + 1, 1):
                    if type_of_packet == 'current_conditions':
                        logdbg('Current conditions received : {}'.format(data))
                        if 'ts' in data['data']:
                            wll_packet['dateTime'] = data['data']['ts']

                        for s in data['data']['conditions']:
                            if s['data_structure_type'] == 1:
                                if s['txid'] == device_id:
                                    if 'temp' in s:
                                        if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[
                                            device_id] == 'iss+':
                                            wll_packet['outTemp'] = s['temp']

                                        if self.dict_device_id[device_id] in 'extraTemp{}'.format(
                                                nmb_device_id):
                                            extraTemp['extraTemp{}'.format(nmb_device_id)] = s['temp']

                                    if 'hum' in s:
                                        if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[
                                            device_id] == 'iss+':
                                            wll_packet['outHumidity'] = s['hum']

                                        if self.dict_device_id[device_id] == 'extraHumid{}'.format(
                                                nmb_device_id):
                                            extraHumid['extraHumid{}'.format(nmb_device_id)] = s[
                                                'hum']

                                    if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[
                                        device_id] == 'iss+':
                                        if 'dew_point' in s:
                                            wll_packet['dewpoint'] = s['dew_point']
                                        if 'heat_index' in s:
                                            wll_packet['heatindex'] = s['heat_index']
                                        if 'wind_chill' in s:
                                            wll_packet['windchill'] = s['wind_chill']

                                    if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[
                                        device_id] == 'iss+' or self.dict_device_id[device_id] == 'extra_Anenometer':
                                        if 'wind_speed_last' in s:
                                            wll_packet['windSpeed'] = s['wind_speed_last']
                                        if 'wind_dir_last' in s:
                                            wll_packet['windDir'] = s['wind_dir_last']

                                        if self.api_parameters['wind_gust_2m_enable'] == 0:
                                            if 'wind_speed_hi_last_10_min' in s:
                                                wll_packet['windGust'] = s['wind_speed_hi_last_10_min']
                                            if 'wind_dir_at_hi_speed_last_10_min' in s:
                                                wll_packet['windGustDir'] = s['wind_dir_at_hi_speed_last_10_min']

                                        if self.api_parameters['wind_gust_2m_enable'] == 1:
                                            if 'wind_speed_hi_last_2_min' in s:
                                                wll_packet['windGust'] = s['wind_speed_hi_last_2_min']
                                            if 'wind_dir_at_hi_speed_last_2_min' in s:
                                                wll_packet['windGustDir'] = s['wind_dir_at_hi_speed_last_2_min']

                                    if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[
                                        device_id] == 'iss+':
                                        if 'rain_rate_last' in s:
                                            rainRate = s['rain_rate_last']
                                        if 'rainfall_daily' in s:
                                            rainFall_Daily = s['rainfall_daily']
                                        if 'rain_size' in s:
                                            rainSize = s['rain_size']

                                    if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[
                                        device_id] == 'iss+':
                                        if 'uv_index' in s:
                                            wll_packet['UV'] = s['uv_index']
                                        if 'solar_rad' in s:
                                            wll_packet['radiation'] = s['solar_rad']

                            # Next lines are not extra, so no need ID

                            if s['data_structure_type'] == 2:
                                pass

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
                                if s['txid'] == device_id:
                                    if self.api_parameters['udp_enable'] == 1:
                                        if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[
                                            device_id] == 'iss+' or self.dict_device_id[
                                            device_id] == 'extra_Anenometer':
                                            if 'wind_speed_last' in s:
                                                udp_wll_packet['windSpeed'] = s['wind_speed_last']
                                            if 'wind_dir_last' in s:
                                                udp_wll_packet['windDir'] = s['wind_dir_last']
                                            if 'wind_speed_hi_last_10_min' in s:
                                                udp_wll_packet['windGust'] = s['wind_speed_hi_last_10_min']
                                            if 'wind_dir_at_hi_speed_last_10_min' in s:
                                                udp_wll_packet['windGustDir'] = s['wind_dir_at_hi_speed_last_10_min']

                                        if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[
                                            device_id] == 'iss+' or self.dict_device_id[device_id] == 'extra_RainGauge':
                                            if 'rain_rate_last' in s:
                                                rainRate = s['rain_rate_last']
                                            if 'rainfall_daily' in s:
                                                rainFall_Daily = s['rainfall_daily']
                                            if 'rain_size' in s:
                                                rainSize = s['rain_size']

            logdbg("rainFall_Daily set : {}".format(rainFall_Daily))

            if self.rain_previous_period is not None:
                rain, rainRate = self.calculate_rain(rainFall_Daily, rainRate, rainSize)

                if rain is not None and rainRate is not None:
                    add_current_rain = {'rain': rain,
                                        'rainRate': rainRate,
                                        }
            else:
                if rainFall_Daily is not None:
                    if rainFall_Daily >= 0:
                        self.rain_previous_period = rainFall_Daily
                        logdbg("rainFall_Daily set by WLLDriver : {}".format(self.rain_previous_period))

            if type_of_packet == 'current_conditions':
                if add_current_rain is not None:
                    wll_packet.update(add_current_rain)

                if len(self.dict_device_id) > 1:
                    if extraTemp is not None:
                        wll_packet.update(extraTemp)

                    if extraHumid is not None:
                        wll_packet.update(extraHumid)

                if wll_packet['dateTime'] is not None:
                    _packet = copy.copy(wll_packet)

                logdbg("Current conditions Weewx packet : {}".format(_packet))

            if type_of_packet == 'realtime_broadcast':
                if add_current_rain is not None:
                    udp_wll_packet.update(add_current_rain)

                logdbg("Realtime broadcast Weewx packet : {}".format(udp_wll_packet))

                if udp_wll_packet['dateTime'] is not None:
                    _packet = copy.copy(udp_wll_packet)

            before_time = time.time() - 120
            after_time = time.time() + 120

            if _packet is not None and _packet['dateTime'] is not None and before_time <= _packet[
                'dateTime'] and after_time >= _packet['dateTime']:
                logdbg("Final packet return to Weewx : {}".format(_packet))
                yield _packet

            else:
                raise weewx.WeeWxIOError('No data in WLL packet but request is OK')

        except KeyError as error:
            raise weewx.WeeWxIOError('API Data from WLL Module is invalid. Error is : {}'.format(error))
        except IndexError as error:
            raise weewx.WeeWxIOError('Structure type is not valid. Error is : {}'.format(error))

    def WLAPIv2(self, start_timestamp=None, end_timestamp=None):

        parameters = {
            "api-key": str(self.api_parameters['wl_apikey']),
            "api-secret": str(self.api_parameters['wl_apisecret']),
            "end-timestamp": str(end_timestamp),
            "start-timestamp": str(start_timestamp),
            "station-id": str(self.api_parameters['wl_stationid']),
            "t": int(time.time())
        }

        parameters = collections.OrderedDict(sorted(parameters.items()))

        apiSecret = parameters["api-secret"];
        parameters.pop("api-secret", None);

        data = ""
        for key in parameters:
            data = data + key + str(parameters[key])

        apiSignature = hmac.new(
            apiSecret.encode('utf-8'),
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        url_wlapiv2 = "https://api.weatherlink.com/v2/historic/{}?api-key={}&t={}&start-timestamp={}&end-timestamp={}&api-signature={}".format(
            parameters["station-id"], parameters["api-key"], parameters["t"], parameters["start-timestamp"],
            parameters["end-timestamp"], apiSignature)

        return url_wlapiv2

    def request_wl(self, start_timestamp, end_timestamp):

        # Function to request archive from Weatherlink.com

        index_start_timestamp = 0
        index_end_timestamp = 1
        dict_timestamp = {}
        index_timestamp = 0

        start_timestamp = self.get_timestamp_by_time(start_timestamp)
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

        for archive_interval in dict_timestamp:
            url_apiv2_wl = self.WLAPIv2(archive_interval[index_start_timestamp], archive_interval[index_end_timestamp])
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

        poll_interval = self.api_parameters['poll_interval']

        if self.udp_countdown - poll_interval < time.time():
            rb = self.request_json_data(self.url_realtime_broadcast, self.api_parameters['time_out'],
                                        'Realtime_broadcast')

            if rb['data'] is not None:
                self.udp_countdown = time.time() + rb['data']['duration']
                return

    def get_realtime_broadcast(self):

        poll_interval = self.api_parameters['poll_interval']

        if self.udp_countdown - poll_interval > time.time():
            try:
                data, wherefrom = comsocket.recvfrom(2048)
                realtime_data = json.loads(data.decode("utf-8"))

                if realtime_data is not None:
                    return realtime_data

            except OSError:
                loginf("Failure to get realtime data")


def loader(config_dict, engine):
    # Define the driver

    return WLLDriver(**config_dict[DRIVER_NAME], **config_dict)


class WLLDriver(weewx.drivers.AbstractDevice):

    def __init__(self, **stn_dict):

        # Define description of driver

        self.vendor = "Davis"
        self.product = "WeatherLinkLive"
        self.model = "WLLDriver"

        # Define values set in weewx.conf

        api_parameters = {}

        api_parameters['max_tries'] = int(stn_dict.get('max_tries', 5))
        api_parameters['time_out'] = int(stn_dict.get('time_out', 10))
        api_parameters['retry_wait'] = int(stn_dict.get('retry_wait', 10))
        api_parameters['poll_interval'] = int(stn_dict.get('poll_interval', 10))
        api_parameters['udp_enable'] = int(stn_dict.get('udp_enable', 0))
        api_parameters['wind_gust_2m_enable'] = int(stn_dict.get('wind_gust_2m_enable', 0))
        api_parameters['hostname'] = (stn_dict.get('hostname', "127.0.0.1"))
        api_parameters['wl_apikey'] = (stn_dict.get('wl_apikey', "ABCABC"))
        api_parameters['wl_apisecret'] = (stn_dict.get('wl_apisecret', "ABCABC"))
        api_parameters['wl_stationid'] = (stn_dict.get('wl_stationid', "ABCABC"))
        api_parameters['wl_archive_interval'] = int(stn_dict.get('wl_archive_interval', 15))
        api_parameters['device_id'] = (stn_dict.get('device_id', str("1:iss")))

        self.poll_interval = api_parameters['poll_interval']
        self.max_tries = api_parameters['max_tries']
        self.retry_wait = api_parameters['retry_wait']
        self.udp_enable = api_parameters['udp_enable']
        self.ntries = 1

        # Define WLLDriverAPI

        self.WLLDriverAPI = WLLDriverAPI(api_parameters)

        # Show description at startup of Weewx

        loginf("driver is %s" % DRIVER_NAME)
        loginf("driver version is %s" % DRIVER_VERSION)
        loginf("polling interval is %s" % self.poll_interval)

    # Function below are defined for Weewx engine :

    @property
    def hardware_name(self):

        # Define hardware name

        return self.model

    def genStartupRecords(self, good_stamp):

        # Generate values since good stamp in Weewx database

        while self.ntries < self.max_tries:
            try:
                now_timestamp_wl = self.WLLDriverAPI.get_timestamp_wl_archive()

                # Add 60 secondes timestamp to wait the WLL archive new data

                if good_stamp is not None and (good_stamp + 60 < now_timestamp_wl):
                    for _packet_wl in self.WLLDriverAPI.request_wl(good_stamp, now_timestamp_wl):
                        yield _packet_wl
                        good_stamp = time.time() + 0.5
                        self.ntries = 1

                else:
                    return

            except weewx.WeeWxIOError as e:
                logerr("Failed attempt %d of %d to get loop data: %s" %
                       (self.ntries, self.max_tries, e))
                self.ntries += 1
                time.sleep(self.retry_wait)
        else:
            return

    def genLoopPackets(self):

        # Make loop packet specify by user by poll interval

        while self.ntries < self.max_tries:

            try:
                for _packet_wll in self.WLLDriverAPI.request_wll('current_conditions'):
                    yield _packet_wll
                    self.ntries = 1

                if self.udp_enable == 0:
                    if self.poll_interval:
                        time.sleep(self.poll_interval)

                if self.udp_enable == 1:
                    timeout_udp_broadcast = time.time() + self.poll_interval

                    self.WLLDriverAPI.request_realtime_broadcast()

                    #if self.poll_interval:
                        #time.sleep(3)

                    while time.time() < timeout_udp_broadcast:
                        for _realtime_packet in self.WLLDriverAPI.request_wll('realtime_broadcast'):
                            yield _realtime_packet
                            self.ntries = 1

            except weewx.WeeWxIOError as e:
                logerr("Failed attempt %d of %d to get loop data: %s" %
                       (self.ntries, self.max_tries, e))
                self.ntries += 1
                time.sleep(self.retry_wait)
        else:
            msg = "Max retries (%d) exceeded for LOOP data" % self.max_tries
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
