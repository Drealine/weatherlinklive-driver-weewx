#!/usr/bin/python3

TEST_URL="http://192.168.1.18:80/v1/current_conditions"


# and now for the driver itself......

DRIVER_NAME = "WLLDriver"
DRIVER_VERSION = "0.2"

import json
import requests
import socket
import urllib.request
import sys
import time
import mysql.connector
import weewx.drivers
import weewx.engine
import weewx.units
import collections
import hashlib
import hmac
import time
import datetime
import math

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

        self.max_tries = int(stn_dict.get('max_tries', 5))
        self.time_out = int(stn_dict.get('time_out', 10))
        self.retry_wait = int(stn_dict.get('retry_wait', 10))
        self.poll_interval = float(stn_dict.get('poll_interval', 10))
        self.udp_enable = int(stn_dict.get('udp_enable',0))
        self.hostname = (stn_dict.get('hostname', "127.0.0.1"))
        self.wl_apikey = (stn_dict.get('wl_apikey', "ABCABC"))
        self.wl_apisecret = (stn_dict.get('wl_apisecret', "ABCABC"))
        self.wl_stationid = (stn_dict.get('wl_stationid', "ABCABC"))
        self.wl_archive_interval = int(stn_dict.get('wl_archive_interval',15))
        device_id = (stn_dict.get('device_id',str("1:iss")))

        # Define URL for current conditions and udp broadcast

        self.url_current_conditions = "http://{}/v1/current_conditions".format(self.hostname)
        self.url_realtime_broadcast = "http://{}/v1/real_time?duration=36000".format(self.hostname)

        # Define values for driver work

        self.update_packet = None
        self.ntries = 1
        self.rain_previous_period = None
        self.udp_countdown = 0        
        self.length_dict_device_id = None
        self.dict_device_id = dict((int(k), v) for k, v in (e.split(':') for e in device_id.split('-')))
        self.length_dict_device_id = len(self.dict_device_id)

        self.dict_sensor_type = {'iss':{46,48},
                                'extraTemp':{55},
                                'extraHumid':{55},
            }

        # Show description at startup of Weewx

        loginf("driver is %s" % DRIVER_NAME)
        loginf("driver version is %s" % DRIVER_VERSION)
        loginf("polling interval is %s" % self.poll_interval)


    def get_timestamp_wl_archive(self, wl_archive_interval):

        # Get the last timestamp of Weatherlink archive interval set in conf driver

        timestamp_wl_archive = int(math.floor((time.time() - 60) / (wl_archive_interval * 60)) * (wl_archive_interval * 60))

        return timestamp_wl_archive

    def get_timestamp_by_time(self, timestamp, wl_archive_interval):

        # Get timestamp from specific time of Weatherlink archive interval set in conf driver

        timestamp_wl_archive = int(math.floor((timestamp - 60) / (wl_archive_interval * 60)) * (wl_archive_interval * 60))

        return timestamp_wl_archive


    def data_decode_wl(self, data, start_timestamp, end_timestamp):

        # Function to decode data from Weatherlink.com

        data_wl = data

        start_timestamp = int(start_timestamp + (60 * self.wl_archive_interval))

        self.length_json = len(data_wl['sensors'])

        while start_timestamp <= end_timestamp:

            logdbg("Request archive from {} to {}".format(start_timestamp, end_timestamp))

            extraTemp = {}
            extraHumid = {}

            outTemp = None
            outHumidity = None
            dewpoint = None
            heatindex = None
            windchill = None
            windSpeed = None
            windDir = None
            windGust = None
            windGustDir = None
            barometer = None
            pressure = None
            rain = None
            rainRate = None
            inTemp = None
            inHumidity = None
            inDewpoint = None

            length_json_count = 0
            length_json = self.length_json - 1

            length_dict_device_id_count = 1
            length_dict_device_id = self.length_dict_device_id

            while length_dict_device_id_count <= length_dict_device_id:

                while length_json_count <= length_json:

                    for device_id, device in self.dict_device_id.items():

                        temp_dict_device_id = self.dict_device_id[device_id]

                        temp_dict_device_id = ''.join([i for i in temp_dict_device_id if not i.isdigit()])

                        for sensor_type_id in self.dict_sensor_type[temp_dict_device_id]:

                            for s in data_wl['sensors']:

                                if s['sensor_type'] == sensor_type_id:

                                    for s in data_wl['sensors'][length_json_count]['data']:

                                        if 'tx_id' in s and s['tx_id'] == device_id:

                                            if s['ts'] == start_timestamp:

                                                if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+' or self.dict_device_id[device_id] in 'extraTemp{}'.format(length_dict_device_id_count):

                                                    if 'temp_last' in s:

                                                        if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+':

                                                            outTemp = s['temp_last']

                                                        if self.dict_device_id[device_id] in 'extraTemp{}'.format(length_dict_device_id_count):

                                                            extraTemp['extraTemp{}'.format(length_dict_device_id_count)] = s['temp_last']

                                                if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+' or 'extraHumid{}'.format(length_dict_device_id_count):

                                                    if 'hum_last' in s:

                                                        if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+':

                                                            outHumidity = s['hum_last']

                                                        if self.dict_device_id[device_id] == 'extraHumid{}'.format(length_dict_device_id_count):

                                                            extraHumid['extraHumid{}'.format(length_dict_device_id_count)] = s['hum_last']

                                                if 'dew_point_last' in s:

                                                    dewpoint = s['dew_point_last']

                                                if 'rain_size' in s:

                                                    rainSize = s['rain_size']
                                                
                                                if 'heat_index_last' in s:

                                                    heatindex = s['heat_index_last']

                                                if 'wind_chill_last' in s:

                                                    windchill = s['wind_chill_last']

                                                if 'wind_speed_avg' in s:

                                                    windSpeed = s['wind_speed_avg']

                                                if 'wind_dir_of_prevail' in s:

                                                    windDir = s['wind_dir_of_prevail']

                                                if 'wind_speed_hi' in s:

                                                    windGust = s['wind_speed_hi']

                                                if 'wind_speed_hi_dir' in s:

                                                    windGustDir = s['wind_speed_hi_dir']

                                                if rainSize is not None:

                                                    if rainSize == 1:

                                                        if 'rain_rate_hi_in' in s:

                                                            rainRate = s['rain_rate_hi_in']

                                                        if 'rainfall_in' in s:

                                                            rain = s['rainfall_in']

                                                    elif rainSize == 2:

                                                        if 'rain_rate_hi_mm' in s:
               
                                                            rainRate = s['rain_rate_hi_mm']

                                                            if rainRate is not None:

                                                                if rainRate > 0:

                                                                    rainRate = float(rainRate) / 25.4

                                                        if 'rainfall_mm' in s:

                                                            rain = s['rainfall_mm']

                                                            if rain is not None:

                                                                if rain > 0:

                                                                    rain = float(rain) / 25.4

                                                    #elif rainSize == 3:

                                                        # What about this value ? Is not implement on weatherlink.com ?

                            for s in data_wl['sensors']:

                                if s['sensor_type'] == 242:

                                    for s in data_wl['sensors'][length_json_count]['data']:

                                        if s['ts'] == start_timestamp:

                                            if 'bar_sea_level' in s:

                                                barometer = s['bar_sea_level']

                                            if 'bar_absolute' in s:

                                                pressure = s['bar_absolute']

                            for s in data_wl['sensors']:

                                if s['sensor_type'] == 243:

                                    for s in data_wl['sensors'][length_json_count]['data']:
                                        
                                        if s['ts'] == start_timestamp:

                                            if 'temp_in_last' in s:

                                                inTemp = s['temp_in_last']

                                            if 'hum_in_last' in s:

                                                inHumidity = s['hum_in_last']

                                            if 'dew_point_in' in s:

                                                inDewpoint = s['dew_point_in']


                    length_json_count += 1

                length_dict_device_id_count += 1
          
            wl_packet = {'dateTime': int(start_timestamp),
                               'usUnits': weewx.US,
                               'interval': self.wl_archive_interval,
                               'outTemp': outTemp,
                               'outHumidity': outHumidity,
                               'dewpoint': dewpoint,
                               'heatindex': heatindex,
                               'windchill': windchill,
                               'windSpeed' : windSpeed,
                               'windDir' : windDir,
                               'windGust' : windGust,
                               'windGustDir' : windGustDir,
                               'barometer' : barometer,
                               'pressure' : pressure,
                               'rain' : rain,
                               'rainRate' : rainRate,
                               'inTemp':  inTemp,
                               'inHumidity':  inHumidity,
                               'inDewpoint' : inDewpoint,
                               }

            if length_dict_device_id_count > 1:

                if extraTemp is not None:

                    wl_packet.update(extraTemp)

                if extraHumid is not None:

                    wl_packet.update(extraHumid)

            if wl_packet is not None:

                logdbg("Packet received from Weatherlink.com :{}".format(wl_packet))
                start_timestamp = int(start_timestamp + (60 * self.wl_archive_interval))
                yield wl_packet

            else:

                raise Exception('No data present in Weatherlink.com packet but request is OK')

        # Keep this line for futur use
        '''if self.poll_interval: 
            time.sleep(self.poll_interval)'''


    def data_decode_wll(self, data, type_of_packet):

        # Function to decode data from WLL module

        extraTemp = {}
        extraHumid = {}

        outTemp = None
        outHumidity = None
        dewpoint = None
        heatindex = None
        windchill = None
        windSpeed = None
        windDir = None
        windGust = None
        windGustDir = None
        barometer = None
        pressure = None
        rainRate = None
        inTemp = None
        inHumidity = None
        inDewpoint = None

        if type_of_packet == 'current_conditions' and data['data'] == None:

            raise Exception('No data in WLL packet')

        else:

            rain_this_period = 0

            for device_id, device in self.dict_device_id.items():

                length_dict_device_id_count = 1
                length_dict_device_id = self.length_dict_device_id

                while length_dict_device_id_count <= length_dict_device_id:

                    if type_of_packet == 'current_conditions':

                        datetime = data['data']['ts']

                        for s in data['data']['conditions']:

                            if s['data_structure_type'] == 1 :

                                if s['txid'] == device_id:

                                    if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+' or self.dict_device_id[device_id] in 'extraTemp{}'.format(length_dict_device_id_count):

                                        if 'temp' in s and s['temp'] is not None:

                                            if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+':
                                
                                                outTemp = s['temp']

                                            elif self.dict_device_id[device_id] in 'extraTemp{}'.format(length_dict_device_id_count):

                                                extraTemp['extraTemp{}'.format(length_dict_device_id_count)] = s['temp']

                                    if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+' or 'extraHumid{}'.format(length_dict_device_id_count):

                                        if 'hum' in s and s['hum'] is not None:

                                            if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+':
                                
                                                outHumidity = s['hum']

                                            elif self.dict_device_id[device_id] == 'extraHumid{}'.format(length_dict_device_id_count):

                                                extraHumid['extraHumid{}'.format(length_dict_device_id_count)] = s['hum']

                                    if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+':

                                        if 'dew_point' in s and s['dew_point'] is not None:

                                            dewpoint = s['dew_point']

                                        if 'heat_index' in s and s['heat_index'] is not None:
                                        
                                            heatindex = s['heat_index']
                                        
                                        if  'wind_chill' in s and s['wind_chill'] is not None:    

                                            windchill = s['wind_chill']

                                    if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+' or self.dict_device_id[device_id] == 'extra_Anenometer':

                                        if 'wind_speed_last' in s:

                                            windSpeed = s['wind_speed_last']

                                        if 'wind_dir_last' in s:

                                            windDir = s['wind_dir_last']
                                        
                                        if 'wind_speed_hi_last_10_min' in s:

                                            windGust = s['wind_speed_hi_last_10_min']

                                        if 'wind_dir_scalar_avg_last_10_min' in s:
                                        
                                            windGustDir = s['wind_dir_scalar_avg_last_10_min']

                                    if self.dict_device_id[device_id] == 'iss' or 'iss+':

                                        if 'rain_rate_last' in s and s['rain_rate_last'] is not None:

                                            rainRate = s['rain_rate_last']

                                        if 'rainfall_daily' in s and s['rainfall_daily'] is not None:

                                            rainFall_Daily = s['rainfall_daily']

                                        if 'rain_size' in s and s['rain_size'] is not None:

                                            rainSize = s['rain_size']

                            # Next lines are not extra, so no need ID

                            elif s['data_structure_type'] == 2 :

                                pass

                            elif s['data_structure_type'] == 3 :

                                barometer = s['bar_sea_level']

                                pressure = s['bar_absolute']

                            elif s['data_structure_type'] == 4 :

                                inTemp = s['temp_in']

                                inHumidity = s['hum_in']

                                inDewpoint = s['dew_point_in']

                    elif type_of_packet == 'realtime_broadcast':

                        datetime = data['ts']

                        for s in data['conditions']:

                            if s['data_structure_type'] == 1 :

                                if s['txid'] == device_id:

                                    if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+' or self.dict_device_id[device_id] == 'extra_Anenometer':

                                        if 'wind_speed_last' in s:

                                            windSpeed = s['wind_speed_last']

                                        if 'wind_dir_last' in s:

                                            windDir = s['wind_dir_last']
                                        
                                        if 'wind_speed_hi_last_10_min' in s:

                                            windGust = s['wind_speed_hi_last_10_min']

                                        if 'wind_dir_at_hi_speed_last_10_min' in s:
                                        
                                            windGustDir = s['wind_dir_at_hi_speed_last_10_min']

                                    if self.dict_device_id[device_id] == 'iss' or self.dict_device_id[device_id] == 'iss+' or self.dict_device_id[device_id] == 'extra_RainGauge':

                                        if 'rain_rate_last' in s and s['rain_rate_last'] is not None:

                                            rainRate = s['rain_rate_last']

                                        if 'rainfall_daily' in s and s['rainfall_daily'] is not None:

                                            rainFall_Daily = s['rainfall_daily']

                                        if 'rain_size' in s and s['rain_size'] is not None:

                                            rainSize = s['rain_size']


                    length_dict_device_id_count += 1


        if rainSize is not None:

            if rainSize == 1:

                rainmultiplier = 0.01

            elif rainSize == 2:

                rainmultiplier = 0.2

            elif rainSize == 3:

                rainmultiplier = 0.1


        if rainFall_Daily is not None: 

            if self.rain_previous_period is not None:
                rain_this_period = (rainFall_Daily - self.rain_previous_period) * rainmultiplier

                if rain_this_period > 0:

                    if rainSize == 2:

                        rain_this_period = rain_this_period / 25.4


                    if rainSize == 3:

                        rain_this_period = rain_this_period / 2.54

                self.rain_previous_period = rainFall_Daily
                logdbg("Rain rightnow is :" + str(rain_this_period))

            else:

                self.rain_previous_period = rainFall_Daily
                logdbg("Rainfall set by WLLDriver")

            logdbg("Set previous period rain to: " + str(self.rain_previous_period))

        if rainRate is not None:

            if rainRate > 0:

                rainRate = rainRate * rainmultiplier

                if rainSize == 2:

                    rainRate = rainRate / 25.4


                if rainSize == 3:

                    rainRate = rainRate / 2.54

                logdbg("rainRate rightnow is : {}".format(rainRate))


        if type_of_packet == 'current_conditions':

            self.update_packet = {'dateTime': datetime,
                   'usUnits': weewx.US,
                   'outTemp': outTemp,
                   'outHumidity': outHumidity,
                   'dewpoint': dewpoint,
                   'heatindex': heatindex,
                   'windchill': windchill,
                   'windSpeed' : windSpeed,
                   'windDir' : windDir,
                   'windGust' : windGust,
                   'windGustDir' : windGustDir,
                   'barometer' : barometer,
                   'pressure' : pressure,
                   'inTemp':  inTemp,
                   'inHumidity':  inHumidity,
                   'inDewpoint' : inDewpoint,
                   }

            if self.udp_enable == 0:

                add_current_rain = {'rain' : rain_this_period,
                    'rainRate' : rainRate,
                    }

                self.update_packet.update(add_current_rain)

            if length_dict_device_id_count > 1:

                if extraTemp is not None:

                    self.update_packet.update(extraTemp)

                if extraHumid is not None:

                    self.update_packet.update(extraHumid)

        elif type_of_packet == 'realtime_broadcast':

            self.update_packet = {'dateTime': datetime,
                   'usUnits': weewx.US,
                   'windSpeed' : windSpeed,
                   'windDir' : windDir,
                   'windGust' : windGust,
                   'windGustDir' : windGustDir,
                   'rain' : rain_this_period,
                   'rainRate' : rainRate,
                   }


        if self.update_packet is not None:

            logdbg("Packet received from WLL module {}:".format(self.update_packet))
            yield self.update_packet

        else:
            
            raise Exception('No data in WLL packet but request is OK')
        

    def get_current_conditions_wll(self):

        # Function to request current conditions from WLL module

        _packet = None

        data = requests.get(url=self.url_current_conditions, timeout=self.time_out)

        if data is not None:

            data = data.json()
            return data


    def request_wl(self,start_timestamp, end_timestamp):

        # Function to request archive from Weatherlink.com

        index_start_timestamp = 0
        index_end_timestamp = 1
        dict_timestamp = {}

        index_timestamp = 0

        start_timestamp = self.get_timestamp_by_time(start_timestamp, self.wl_archive_interval)

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


        wl_packet = None

        for archive_interval in dict_timestamp:

            parameters = {
              "api-key": str(self.wl_apikey),
              "api-secret": str(self.wl_apisecret),
              "end-timestamp": str(archive_interval[index_end_timestamp]),
              "start-timestamp": str(archive_interval[index_start_timestamp]),
              "station-id": str(self.wl_stationid),
              "t": int(time.time())
            }

            parameters = collections.OrderedDict(sorted(parameters.items()))

            for key in parameters:
              print("Parameter name: \"{}\" has value \"{}\"".format(key, parameters[key]))

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

            url_apiv2_wl = "https://api.weatherlink.com/v2/historic/{}?api-key={}&t={}&start-timestamp={}&end-timestamp={}&api-signature={}".format(parameters["station-id"], parameters["api-key"], parameters["t"], parameters["start-timestamp"], parameters["end-timestamp"], apiSignature)
            logdbg("URL API Weatherlink is {} ".format(url_apiv2_wl))

            wl_session = requests.session()
            data_request_url = wl_session.get(url_apiv2_wl, timeout=self.time_out)
            data_wl = data_request_url.json()

            for _packet_wl in self.data_decode_wl(data_wl, archive_interval[index_start_timestamp], archive_interval[index_end_timestamp]):

                if _packet_wl is not None:

                    yield _packet_wl


    def request_realtime_broadcast(self):

        if self.udp_countdown - self.poll_interval < time.time():

            response = requests.get(url=self.url_realtime_broadcast, timeout=self.time_out)

            if response is not None:

                data = response.json()

                if data['data'] is not None:

                    self.udp_countdown = time.time() + data['data']['duration']

                    return


    def get_realtime_broadcast(self):

        if self.udp_countdown - self.poll_interval > time.time():

            try:

                data, wherefrom = comsocket.recvfrom(2048)
                realtime_data = json.loads(data.decode("utf-8"))

                if realtime_data is not None:

                    return realtime_data

            except OSError:
                    loginf("Failure to get realtime data")
                    self.request_realtime_broadcast()

                    

    # Function below are defined for Weewx engine :

    @property
    def hardware_name(self):

        # Define hardware name

        return self.model


    def genStartupRecords(self, good_stamp):

        # Generate values since good stamp in Weewx database

        while self.ntries < self.max_tries:

            try:

                now_timestamp_wl = self.get_timestamp_wl_archive(self.wl_archive_interval)

                # Add 60 secondes timestamp to wait the WLL archive new data

                if good_stamp is not None and (good_stamp + 60 < now_timestamp_wl):

                    for _packet_wl in self.request_wl(good_stamp, now_timestamp_wl):

                        yield _packet_wl
                        good_stamp = time.time() + 0.5
                        self.ntries = 1

                else:

                    return

            except requests.exceptions.RequestException as e:
                logerr("Failed attempt %d of %d to get LOOP data: %s" %
                       (self.ntries, self.max_tries, e))

                self.ntries += 1
                time.sleep(self.retry_wait)

            except UnboundLocalError as e:
                logerr("Failed attempt %d of %d to get LOOP data: %s" %
                       (self.ntries, self.max_tries, e))

                self.ntries += 1
                time.sleep(self.retry_wait)
        else:
            
            return

    def genLoopPackets(self):

        # Make loop packet specify by user by poll interval

        while self.ntries < self.max_tries:

            try:

                conditions_data = self.get_current_conditions_wll()
                

                if conditions_data is not None:

                    for _packet_wll in self.data_decode_wll(conditions_data, 'current_conditions'):

                            yield _packet_wll
                            self.ntries = 1

                if self.udp_enable == 0:

                    if self.poll_interval:

                        time.sleep(self.poll_interval)


                if self.udp_enable == 1:

                    timeout_udp_broadcast = time.time() + self.poll_interval

                    self.request_realtime_broadcast()

                    while time.time() < timeout_udp_broadcast:

                        realtime_data = self.get_realtime_broadcast()

                        if realtime_data is not None:

                            for _realtime_packet in self.data_decode_wll(realtime_data, 'realtime_broadcast'):

                                yield _realtime_packet
                                self.ntries = 1

            except requests.exceptions.RequestException as e:
                logerr("Failed attempt %d of %d to get loop data: %s" %
                       (self.ntries, self.max_tries, e))

                self.ntries += 1
                time.sleep(self.retry_wait)

            except UnboundLocalError as e:
                logerr("Failed attempt %d of %d to get loop data: %s" %
                       (self.ntries, self.max_tries, e))

                self.ntries += 1
                time.sleep(self.retry_wait)

        else:
            msg = "Max retries (%d) exceeded for LOOP data" % self.max_tries
            logerr(msg)
            raise weewx.RetriesExceeded(msg)


#==============================================================================
# Main program
#
# To test this driver, do the following:
#   PYTHONPATH="Path of your 'bin' folder specific of your Weewx installation" python3 /home/weewx/bin/user/WLLDriver.py
#
#==============================================================================

if __name__ == "__main__":
    usage = """%prog [options] [--help]"""

    def main():
        try:
            import logging
            import weeutil.logger
            log = logging.getLogger(__name__)
            weeutil.logger.setup('WLLDriver', {} )
        except ImportError:
            import syslog
            syslog.openlog('WLLDriver', syslog.LOG_PID | syslog.LOG_CONS)

        import optparse
        parser = optparse.OptionParser(usage=usage)
        parser.add_option('--test-driver', dest='td', action='store_true',
                          help='test the driver')
        (options, args) = parser.parse_args()

        if  options.td:
            test_driver()

    def test_driver():
        import weeutil.weeutil
        driver = WLLDriver()
        print("testing driver")
        for pkt in driver.genLoopPackets():
            print((weeutil.weeutil.timestamp_to_string(pkt['dateTime']), pkt))

    main()
